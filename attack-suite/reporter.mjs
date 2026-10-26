// A node:test reporter that writes one JSON line per finished test: its name,
// file and outcome. report.mjs passes it to every suite it runs.
export default async function* jsonLines(source) {
  for await (const { type, data } of source) {
    if (type !== 'test:pass' && type !== 'test:fail') continue;
    if (data.details?.type === 'suite') continue;
    const outcome = type === 'test:fail' ? 'fail' : data.skip !== undefined ? 'skip' : data.todo !== undefined ? 'todo' : 'pass';
    yield `${JSON.stringify({ name: data.name, file: data.file ?? null, outcome })}\n`;
  }
}
