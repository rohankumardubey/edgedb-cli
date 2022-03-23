use crate::cloud::auth;
use crate::print;
use crate::question;

#[derive(Debug, thiserror::Error)]
#[error("HTTP error: {0}")]
pub struct HttpError(surf::Error);

pub fn create(
    _cmd: &crate::portable::options::Create,
    opts: &crate::options::Options,
) -> anyhow::Result<()> {
    println!(
        "cloud create: {:?}",
        auth::get_access_token(&opts.cloud_options)?
    );
    Ok(())
}

pub async fn link(
    cmd: &crate::portable::options::Link,
    opts: &crate::options::Options,
) -> anyhow::Result<()> {
    let options = &opts.cloud_options;
    let base_url = auth::get_base_url(options);
    let access_token = if let Some(access_token) = auth::get_access_token(options)? {
        access_token
    } else {
        if cmd.non_interactive {
            anyhow::bail!("Run `edgedb cloud login` first.");
        } else {
            let q = question::Confirm::new(
                "You're not authenticated to the EdgeDB Cloud yet, login now?",
            );
            if q.ask()? {
                auth::login(&crate::cloud::options::Login {}, options).await?;
                if let Some(access_token) = auth::get_access_token(options)? {
                    access_token
                } else {
                    anyhow::bail!("Couldn't fetch access token.");
                }
            } else {
                print::error("Aborted.");
                return Ok(())
            }
        }
    };
    let instance_id = if cmd.non_interactive {
        anyhow::bail!("Not implemented.");
    } else {
        question::String::new("Input the EdgeDB Cloud instance ID to connect to").ask()?
    };
    let mut resp = surf::get(format!("{}/v1/edgedb-instances/{}", base_url, instance_id))
        .header("Authorization", access_token) // TODO(fantix): fix auth
        .await
        .map_err(HttpError)?;
    auth::raise_http_error(&mut resp).await?;

    println!("resp: {}", resp.body_string().await.map_err(HttpError)?);
    // TODO(fantix): create cloud instance with response
    Ok(())
}
