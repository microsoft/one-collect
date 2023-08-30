pub enum SessionEgress<'a> {
    File(FileSessionEgress<'a>),
    Live,
}

pub struct FileSessionEgress<'a> {
    path: &'a str,
}

impl<'a> FileSessionEgress<'a> {
    pub fn new(path: &'a str) -> Self {
        FileSessionEgress {
            path
        }
    }

    pub fn get_path(&self) -> &str {
        self.path
    }
}

pub struct SessionBuilder<'a> {
    egress: SessionEgress<'a>,
}

impl<'a> SessionBuilder<'a> {
    pub fn new(egress: SessionEgress<'a>) -> Self {
        SessionBuilder {
            egress
        }
    }

    pub fn build(self) -> Session<'a> {
        Session::new(self)
    }
}

pub struct Session<'a> {
    egress: SessionEgress<'a>,
}

impl<'a> Session<'a> {
    pub(crate) fn new(builder: SessionBuilder<'a>) -> Self {
        Session {
            egress: builder.egress
        }
    }

    pub fn get_egress_info(&self) -> &SessionEgress<'a> {
        &self.egress
    }
}