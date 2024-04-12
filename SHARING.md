# Quick access to shared details

Often times we need to share details between closures. Sometimes you want closures to be able to update this data and
other times you don't. To achieve this we have Writable and ReadOnly structs which can hold any type of value.

For Writable shared data, you can call read() or write() which both take a closure. The shared data is then only shared
until the closure exits. Sometimes you want to not have to write a closure for this, so you can alternatively use
borrow() and borrow_mut() where the shared data is then borrowed until the returned object is dropped.

For ReadOnly shared data, it is the same, but write() and borrow_mut() are not available.

It's entirely possible (and well supported) that some parts of the pipeline have Writable shared data, but give it out
as ReadOnly data. For this, the Writable object has read_only() which creates a ReadOnly shared data for the same data.

Both Writable and ReadOnly shared data can be moved to closures via the clone() method. This allows multiple views
of the underlying data to easily be shared across any number of closures.
