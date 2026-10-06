// Id helpers. Written against the uuid 3.x API, where each version is its own module.
const uuidv4 = require("uuid/v4");
const uuidv5 = require("uuid/v5");

// Fixed namespace so the same tag name always maps to the same id.
const TAG_NAMESPACE = "6ba7b810-9dad-11d1-80b4-00c04fd430c8";

/** A random id for a new note. */
function newNoteId() {
  return uuidv4();
}

/** A stable id derived from the tag name. */
function tagId(name) {
  return uuidv5(name.toLowerCase(), TAG_NAMESPACE);
}

module.exports = { newNoteId, tagId };
