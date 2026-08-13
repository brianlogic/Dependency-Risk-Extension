const _ = require("lodash");
const minimist = require("minimist");

const args = minimist(process.argv.slice(2));
console.log(_.get(args, "name", "sample"));
