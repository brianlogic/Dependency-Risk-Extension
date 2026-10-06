const _ = require("lodash");
const { newNoteId, tagId } = require("./ids");

const notes = [];

/** Adds a note and returns it. Tags are de-duplicated and given stable ids. */
function addNote(title, tags = []) {
  const note = {
    id: newNoteId(),
    title,
    tags: _.uniq(tags).map((name) => ({ id: tagId(name), name })),
    createdAt: new Date().toISOString(),
  };
  notes.push(note);
  return note;
}

/** Notes newest first, optionally filtered to one tag name. */
function listNotes(tag) {
  const matching = tag ? notes.filter((n) => _.some(n.tags, { name: tag })) : notes;
  return _.orderBy(matching, ["createdAt"], ["desc"]);
}

/** Note counts per tag name, e.g. { work: 2, home: 1 }. */
function countByTag() {
  return _.countBy(_.flatMap(notes, (n) => n.tags.map((t) => t.name)));
}

module.exports = { addNote, listNotes, countByTag };
