use rhai::Engine;

pub struct ScriptEngine {
    engine: Engine,
}

impl ScriptEngine {
    pub fn new() -> Self {
        Self {
            engine: Engine::new(),
        }
    }

    pub(crate) fn rhai_engine(&mut self) -> &mut Engine { &mut self.engine }

    pub fn eval<T: Clone + 'static>(
        &self,
        script: &str) -> anyhow::Result<T> {
        match self.engine.eval(script) {
            Ok(value) => { Ok(value) },
            Err(err) => {
                anyhow::bail!("Error: {}", err);
            }
        }
    }

    pub fn run(
        &self,
        script: &str) -> anyhow::Result<()> {
        match self.engine.run(script) {
            Ok(()) => { Ok(()) },
            Err(err) => {
                anyhow::bail!("Error: {}", err);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_works() {
        let engine = ScriptEngine::new();

        let i = engine.eval::<i64>("42").unwrap();

        assert_eq!(42, i);
    }
}
