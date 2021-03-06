use edgedb_client::client::Connection;
use edgedb_client::model::Duration;
use edgeql_parser::helpers::quote_string;


pub async fn inhibit_for_transaction(cli: &mut Connection)
    -> Result<Duration, anyhow::Error>
{
    let old_timeout = cli.query_row::<Duration, _>(
        "SELECT cfg::Config.session_idle_transaction_timeout", &()).await?;
    cli.execute("CONFIGURE SESSION SET session_idle_transaction_timeout \
                     := <std::duration>'0'").await?;
    Ok(old_timeout)
}

pub async fn restore_for_transaction(cli: &mut Connection, old: Duration)
    -> Result<(), anyhow::Error>
{
    cli.execute(format!(
       "CONFIGURE SESSION SET session_idle_transaction_timeout \
           := <std::duration>{}",
       quote_string(&old.to_string())
    )).await?;
    Ok(())
}
