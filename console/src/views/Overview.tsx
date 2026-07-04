import { Panel } from '../components/Panel';

export default function Overview() {
  return (
    <Panel title="Overview" meta="preview">
      <p className="app-note">
        This is the new PromptWall console shell. Views are ported from the legacy console one at a
        time; anything not yet available here remains in the classic console at{' '}
        <a href="/index.html">/index.html</a>.
      </p>
    </Panel>
  );
}
