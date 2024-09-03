pub struct CallstackReader {
    /* Placeholder */
}

impl Clone for CallstackReader {
    fn clone(&self) -> Self {
        Self {
            /* Placeholder */
        }
    }
}

pub struct CallstackHelper {
    /* Placeholder */
}

impl CallstackHelper {
    pub fn new() -> Self {
        Self {
            /* Placeholder */
        }
    }

    pub fn with_external_lookup(self) -> Self {
        /* NOP on Windows */
        self
    }

    pub fn to_reader(self) -> CallstackReader {
        CallstackReader {
            /* Placeholder */
        }
    }
}
