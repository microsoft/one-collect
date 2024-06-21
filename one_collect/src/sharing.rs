use std::marker::PhantomData;
use std::cell::RefCell;
use std::rc::Rc;

pub struct DataOwner;
pub struct DataReader;

/// The Writable type alias is a version of SharedData where the data can be both read and modified. It is parameterized over the type of the data `T`.
///
/// It is used when you want to have a shared ownership of some data `T` and you want to be able to both read and write to that data.
///
/// # Examples
///
/// ```
/// use one_collect::Writable;
///
/// let shared_data: Writable<i32> = Writable::new(5);
/// shared_data.write(|data| *data += 1);
/// let new_value = shared_data.value();
/// assert_eq!(new_value, 6);
/// ```
pub type Writable<T> = SharedData<T, DataOwner>;

/// The ReadOnly type alias is a version of SharedData where the data can only be read. It is parameterized over the type of the data `T`.
///
/// It is used when you want to have a shared ownership of some data `T` and you want to prevent modifications to that data.
///
/// # Examples
///
/// ```
/// use one_collect::{Writable, ReadOnly};
///
/// let shared_data: ReadOnly<i32> = Writable::new(5).read_only();
/// shared_data.read(|data| println!("{}", data));
/// ```
pub type ReadOnly<T> = SharedData<T, DataReader>;

/// The SharedData struct is a way to handle shared data in a safe way.
/// It is parameterized over the type of the data `T`, and the state `S` which is either `DataOwner` or `DataReader`.
///
/// It has an `inner` field which is a `Rc<RefCell<T>>` allowing shared ownership and mutable access to the inner data,
/// and a `state` field which is a `PhantomData<S>` to handle the state of the data.
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
    /// Allows to read the data by providing a function that takes an immutable reference of the data.
    ///
    /// # Examples
    ///
    /// ```
    /// use one_collect::Writable;
    ///
    /// let shared_data: Writable<i32> = Writable::new(5);
    /// shared_data.read(|data| println!("{}", data));
    /// ```
    pub fn read(
        &self,
        f: impl FnOnce(&T)) {
        f(&self.inner.borrow());
    }

    /// Allows to modify the data by providing a function that takes a mutable reference of the data.
    ///
    /// # Examples
    ///
    /// ```
    /// use one_collect::Writable;
    ///
    /// let shared_data: Writable<i32> = Writable::new(5);
    /// shared_data.write(|data| *data += 1);
    /// ```
    pub fn write(
        &self,
        f: impl FnOnce(&mut T)) {
        f(&mut self.inner.borrow_mut());
    }

    /// Allows to borrow the data mutably, returning a mutable reference to the data. The data is
    /// borrowed until the returned reference is dropped.
    ///
    /// # Examples
    ///
    /// ```
    /// use one_collect::Writable;
    ///
    /// let shared_data: Writable<i32> = Writable::new(5);
    /// let mut data_ref: std::cell::RefMut<'_, i32> = shared_data.borrow_mut();
    /// *data_ref += 1;
    /// ```
    pub fn borrow_mut(&self) -> std::cell::RefMut<'_, T> {
        self.inner.borrow_mut()
    }

    /// Allows to borrow the data , returning an immutable reference to the data. The data is
    /// borrowed until the returned reference is dropped.
    ///
    /// # Examples
    ///
    /// ```
    /// use one_collect::Writable;
    ///
    /// let shared_data: Writable<i32> = Writable::new(5);
    /// let data_ref: std::cell::Ref<'_, i32> = shared_data.borrow();
    /// println!("{}", *data_ref);
    /// ```
    pub fn borrow(&self) -> std::cell::Ref<'_, T> {
        self.inner.borrow()
    }

    /// Creates a read-only version of the shared data. These will continue to get updates from
    /// existing Writable references. You can use this to safely share data in multiple places
    /// while having a single (or few) places that can update that data.
    ///
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
    /// Allows to borrow the data , returning an immutable reference to the data. The data is
    /// borrowed until the returned reference is dropped.
    ///
    /// # Examples
    ///
    /// ```
    /// use one_collect::{ReadOnly, Writable};
    ///
    /// let shared_data: ReadOnly<i32> = Writable::new(5).read_only();
    /// let data_ref: std::cell::Ref<'_, i32> = shared_data.borrow();
    /// println!("{}", *data_ref);
    /// ```
    pub fn borrow(&self) -> std::cell::Ref<'_, T> {
        self.inner.borrow()
    }

    /// Allows to read the data by providing a function that takes an immutable reference of the data.
    ///
    /// # Examples
    ///
    /// ```
    /// use one_collect::Writable;
    ///
    /// let shared_data: Writable<i32> = Writable::new(5);
    /// shared_data.read(|data| println!("{}", data));
    /// ```
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

