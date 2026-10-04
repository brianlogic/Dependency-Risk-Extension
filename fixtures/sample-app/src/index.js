const minimist = require("minimist");
const ansiRegex = require("ansi-regex");
const { addNote, listNotes, countByTag } = require("./notes");

const red = (s) => `\u001b[31m${s}\u001b[0m`;
const plain = (s) => s.replace(ansiRegex(), "");

const args = minimist(process.argv.slice(2));

// Demo data so `npm start` prints something without any setup.
addNote("Write the README", ["docs", "work"]);
addNote("Buy milk", ["home"]);
addNote(args.title || "Review dependency risks", ["work", "security"]);

const tag = args.tag;
for (const note of listNotes(tag)) {
  const tags = note.tags.map((t) => t.name).join(", ");
  console.log(plain(`${note.id}  ${red(note.title)}  [${tags}]`));
}
console.log("By tag:", countByTag());
