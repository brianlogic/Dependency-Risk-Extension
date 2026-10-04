const _ = require("lodash");
const minimist = require("minimist");

const args = minimist(process.argv.slice(2));
console.log(_.get(args, "name", "sample"));
const ansiRegex = require("ansi-regex");
console.log(ansiRegex().test("\u001b[31mred\u001b[0m"));
