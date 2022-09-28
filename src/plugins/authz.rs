use std::collections::HashSet;
use std::ops::ControlFlow;
use std::sync::Arc;

use anyhow::Result;
use apollo_compiler::values::Directive;
use apollo_compiler::values::FieldDefinition;
use apollo_compiler::values::OperationDefinition;
use apollo_compiler::values::Selection;
use apollo_compiler::values::Value;
use apollo_compiler::ApolloCompiler;
use apollo_router::graphql;
use apollo_router::layers::ServiceBuilderExt;
use apollo_router::plugin::Plugin;
use apollo_router::plugin::PluginInit;
use apollo_router::register_plugin;
use apollo_router::services::execution;
use apollo_router::services::subgraph;
use apollo_router::services::supergraph;
use apollo_router::services::supergraph::Request;
use http::HeaderMap;
use http::HeaderValue;
use jsonwebtoken::Algorithm;
use jsonwebtoken::DecodingKey;
use jsonwebtoken::Validation;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use tower::BoxError;
use tower::{ServiceBuilder, ServiceExt};

#[derive(Debug)]
struct Authz {
    #[allow(dead_code)]
    configuration: Conf,
    supergraph_sdl: Arc<String>,
}

#[derive(Debug, Default, Deserialize, JsonSchema)]
struct Conf {
    // Put your plugin configuration here. It will automatically be deserialized from JSON.
    // Always put some sort of config here, even if it is just a bool to say that the plugin is enabled,
    // otherwise the yaml to enable the plugin will be confusing.
    message: String,
}

// This is a bare bones plugin that can be duplicated when creating your own.
#[async_trait::async_trait]
impl Plugin for Authz {
    type Config = Conf;

    async fn new(init: PluginInit<Self::Config>) -> Result<Self, BoxError> {
        tracing::info!("{}", init.config.message);
        Ok(Authz {
            configuration: init.config,
            supergraph_sdl: init.supergraph_sdl,
        })
    }

    fn supergraph_service(&self, service: supergraph::BoxService) -> supergraph::BoxService {
        let sdl = self.supergraph_sdl.clone();
        ServiceBuilder::new()
            .checkpoint(move |req: Request| {
                let operation = req
                    .supergraph_request
                    .body()
                    .query
                    .as_ref()
                    .expect("operation text missing");
                let operation_name = req.supergraph_request.body().operation_name.as_deref();
                let compiler = ApolloCompiler::new(format!("{}\n{}", sdl, operation).as_str());

                let required = collect_required_scopes(compiler, operation_name)?;
                let token = authorization_token(req.supergraph_request.headers())?;

                if !required.requires_auth {
                    return Ok(ControlFlow::Continue(req));
                }

                if required.requires_auth && token.is_none() {
                    let res = supergraph::Response::error_builder()
                        .error(
                            graphql::Error::builder()
                                .message("authentication required")
                                .build(),
                        )
                        .context(req.context)
                        .build()?;
                    return Ok(ControlFlow::Break(res));
                }

                #[derive(Debug, Serialize, Deserialize)]
                struct Claims {
                    scopes: HashSet<String>,
                }

                let jwt = jsonwebtoken::decode::<Claims>(
                    token.expect("qed").as_str(),
                    &DecodingKey::from_secret("12345".as_ref()),
                    &Validation::new(Algorithm::HS256),
                )?;

                let missing_required_scopes: HashSet<_> =
                    required.scopes.difference(&jwt.claims.scopes).collect();

                if !missing_required_scopes.is_empty() {
                    let res = supergraph::Response::error_builder()
                        .error(
                            graphql::Error::builder()
                                .message(format!(
                                    "missing required scopes: {}",
                                    missing_required_scopes
                                        .into_iter()
                                        .map(|s| s.to_owned())
                                        .collect::<Vec<_>>()
                                        .join(", ")
                                ))
                                .build(),
                        )
                        .context(req.context)
                        .build()?;
                    return Ok(ControlFlow::Break(res));
                }

                Ok(ControlFlow::Continue(req))
            })
            .service(service)
            .boxed()
    }

    // Delete this function if you are not customizing it.
    fn execution_service(&self, service: execution::BoxService) -> execution::BoxService {
        service
    }

    // Delete this function if you are not customizing it.
    fn subgraph_service(&self, _name: &str, service: subgraph::BoxService) -> subgraph::BoxService {
        service
    }
}

fn authorization_token(headers: &HeaderMap<HeaderValue>) -> Result<Option<String>> {
    let value = headers.get("Authorization");

    let value = match value {
        Some(v) => v,
        None => return Ok(None),
    };

    let value = value.to_str()?;

    if value.starts_with("Bearer ") {
        return Ok(value.split(" ").last().map(|s| s.to_string()));
    }

    Ok(None)
}

type ScopeSet = HashSet<String>;

#[derive(Default)]
struct RequiredScopes {
    scopes: ScopeSet,
    requires_auth: bool,
}

fn collect_required_scopes(
    ctx: ApolloCompiler,
    operation_name: Option<&str>,
) -> Result<RequiredScopes> {
    let operation = ctx
        .operation_by_name(operation_name)
        .expect("operation exists");

    let mut required_scopes = RequiredScopes::default();

    fn recurse_selections(
        selections: &[Selection],
        ctx: &ApolloCompiler,
        required_scopes: &mut RequiredScopes,
    ) {
        for selection in selections {
            match selection {
                Selection::Field(f) => {
                    if let Some(def) = f.field_definition(&ctx.db) {
                        if has_directive(&def, "authz") {
                            required_scopes.requires_auth = true;
                        }

                        let scopes = def
                            .directives()
                            .iter()
                            .flat_map(|d| string_argument_values(d, "scope"))
                            .collect::<Vec<_>>();

                        for scope in scopes {
                            required_scopes.scopes.insert(scope);
                        }
                    }

                    recurse_selections(f.selection_set().selection(), ctx, required_scopes);
                }
                Selection::FragmentSpread(f) => {
                    if let Some(fragment) = f.fragment(&ctx.db) {
                        recurse_selections(
                            fragment.selection_set().selection(),
                            ctx,
                            required_scopes,
                        );
                    }
                }
                Selection::InlineFragment(f) => {
                    recurse_selections(f.selection_set().selection(), ctx, required_scopes);
                }
            }
        }
    }

    recurse_selections(
        operation.selection_set().selection(),
        &ctx,
        &mut required_scopes,
    );

    Ok(required_scopes)
}

fn has_directive(f: &FieldDefinition, name: &str) -> bool {
    for d in f.directives() {
        if d.name() == name {
            return true;
        }
    }
    false
}

fn string_argument_values(d: &Directive, name: &str) -> Vec<String> {
    d.arguments()
        .iter()
        .filter(|a| a.name() == name)
        .flat_map(|a| value_strings(a.value()))
        .collect::<Vec<_>>()
}

fn value_strings(v: &Value) -> Vec<String> {
    match v {
        Value::String(s) => vec![s.to_string()],
        Value::List(ss) => ss
            .iter()
            .filter_map(|v| match v {
                Value::String(s) => Some(s.clone()),
                _ => None,
            })
            .collect::<Vec<_>>(),
        _ => vec![],
    }
}

pub trait CompilerAdditions {
    fn operation_by_name(&self, operation_name: Option<&str>) -> Option<OperationDefinition>;
}

impl CompilerAdditions for ApolloCompiler {
    fn operation_by_name(&self, operation_name: Option<&str>) -> Option<OperationDefinition> {
        if let Some(op_name) = operation_name {
            if let Some(operation) = self
                .operations()
                .iter()
                .find(|op| op.name().unwrap_or_default().eq(op_name))
            {
                return Some(operation.clone());
            }
        } else if self.operations().len() == 1 {
            return Some(self.operations().first().expect("qed").clone());
        }

        None
    }
}

// This macro allows us to use it in our plugin registry!
// register_plugin takes a group name, and a plugin name.
register_plugin!("router_authz", "authz", Authz);

#[cfg(test)]
mod tests {
    use apollo_router::services::supergraph;
    use apollo_router::TestHarness;
    use tower::BoxError;
    use tower::ServiceExt;

    #[tokio::test]
    async fn basic_test() -> Result<(), BoxError> {
        let test_harness = TestHarness::builder()
            .configuration_json(serde_json::json!({
                "plugins": {
                    "router_authz.authz": {
                        "message" : "Starting my plugin"
                    }
                }
            }))
            .unwrap()
            .build()
            .await
            .unwrap();
        let request = supergraph::Request::canned_builder().build().unwrap();
        let mut streamed_response = test_harness.oneshot(request).await?;

        let first_response = streamed_response
            .next_response()
            .await
            .expect("couldn't get primary response");

        assert!(first_response.data.is_some());

        println!("first response: {:?}", first_response);
        let next = streamed_response.next_response().await;
        println!("next response: {:?}", next);

        // You could keep calling .next_response() until it yields None if you're expexting more parts.
        assert!(next.is_none());
        Ok(())
    }
}
