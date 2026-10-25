// Synthetic review fixture. This file is read as text, never executed.
const { NodeVM: ReviewVM } = require('vm2');
const sandbox = new ReviewVM({ nesting: true, require: [] });
sandbox.run(operatorSuppliedCode);
