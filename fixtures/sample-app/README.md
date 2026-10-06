# Sample app

A tiny notes script used to try the extension. Open this folder in the extension host (F5) and look at the warnings in `package.json`.

`uuid` 3.4.0 has a known advisory whose only fix is a major upgrade. `src/ids.js` uses the 3.x API (`require("uuid/v4")`), which no longer exists in the fixed versions, so applying the safe fix breaks `npm start` until the imports are updated. That is the case to hand to an AI agent: use **Ask Agent to Upgrade + Fix**.

```bash
npm install
npm start
```

`npm run fixture:reset` from the repo root restores everything.
