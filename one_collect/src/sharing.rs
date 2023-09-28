use std::marker::PhantomData;
use std::cell::RefCell;
use std::rc::Rc;

pub struct DataOwner;
pub struct DataReader;

pub type Writable<T> = SharedData<T, DataOwner>;
pub type ReadOnly<T> = SharedData<T, DataReader>;

pub struct SharedData<T, S = DataOwner> {
    inner: Rc<RefCell<T>>,
    state: PhantomData<S>,
}

impl<T> SharedData<T> {
    pub fn new(value: T) -> SharedData<T, DataOwner> {
        SharedData::<T, DataOwner> {
            inner: Rc::new(RefCell::new(value)),
            state: PhantomData::<DataOwner>,
        }
    }
}

impl<T> SharedData<T, DataOwner> {
    pub fn read(
        &self,
        f: impl FnOnce(&T)) {
        f(&self.inner.borrow());
    }

    pub fn write(
        &self,
        f: impl FnOnce(&mut T)) {
        f(&mut self.inner.borrow_mut());
    }

    pub fn borrow_mut(&self) -> std::cell::RefMut<'_, T> {
        self.inner.borrow_mut()
    }

    pub fn borrow(&self) -> std::cell::Ref<'_, T> {
        self.inner.borrow()
    }

    pub fn read_only(&self) -> SharedData<T, DataReader> {
        SharedData::<T, DataReader> {
            inner: self.inner.clone(),
            state: PhantomData::<DataReader>,
        }
    }
}

impl<T> Clone for SharedData<T, DataOwner> {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
            state: self.state,
        }
    }
}

impl<T: Copy> SharedData<T, DataOwner> {
    pub fn set(
        &self,
        value: T) {
        *self.inner.borrow_mut() = value;
    }

    pub fn value(&self) -> T {
        *self.inner.borrow()
    }
}

impl<T> SharedData<T, DataReader> {
    pub fn borrow(&self) -> std::cell::Ref<'_, T> {
        self.inner.borrow()
    }

    pub fn read(
        &self,
        f: impl FnOnce(&T)) {
        f(&self.inner.borrow());
    }
}

impl<T> Clone for SharedData<T, DataReader> {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
            state: self.state,
        }
    }
}

impl<T: Copy> SharedData<T, DataReader> {
    pub fn value(&self) -> T {
        *self.inner.borrow()
    }
}

