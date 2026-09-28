use l2tpv3d::config::Config;
use schemars::schema_for;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let schema = schema_for!(Config);
    println!("{}", serde_json::to_string_pretty(&schema)?);
    Ok(())
}
