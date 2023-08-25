pub enum SessionStorage<'a> {
    File(FileSessionArgs<'a>),
    InMemory
}

pub struct FileSessionArgs<'a> {
    path: &'a str
}

impl<'a> FileSessionArgs<'a> {
    pub fn new(path: &'a str) -> Self {
        FileSessionArgs {
            path
        }
    }

    pub fn get_path(&self) -> &'a str {
        &self.path
    }
}

pub struct OneCollectSession<'a> {
    storage : SessionStorage<'a>,
}

impl<'a> OneCollectSession<'a> {
    pub fn new(storage: SessionStorage<'a>) -> Self {
        OneCollectSession {
            storage
        }
    }

    pub fn get_storage(&self) -> &SessionStorage<'a> {
        &self.storage
    }
}