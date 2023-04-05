use chrono::prelude::*;

fn main() {
  let utc: DateTime<Utc> = Utc::now();
  println!("Hello World at {}", utc)
}
