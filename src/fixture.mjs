// fixture.mjs - a small world the tests and the benchmark both build on.

import { createControlPlane } from '../src/control-plane.mjs';

export function manualClock(startIso) {
  let t = new Date(startIso || '2026-10-02T00:00:00.000Z').getTime();
  return {
    now: () => new Date(t).toISOString(),
    advance(ms) { t += ms; },
  };
}

export async function makeWorld(options) {
  const opts = options || {};
  const clock = opts.clock || manualClock();
  const calls = [];
  const spyExecutor = async (invocation) => {
    calls.push(invocation);
    return { ok: true, action: invocation.action, target: invocation.target };
  };
  const cp = await createControlPlane({
    clock: clock.now,
    executor: opts.executor || spyExecutor,
    governance: opts.governance,
    grantTtlMs: opts.grantTtlMs,
    // The fixture asks for the privileged surface because its adversarial cases simulate an
    // already-compromised process (tampering with a stored definition, driving the governance
    // engine into a block). Pass internals:false to get exactly the surface a runner would get.
    internals: opts.internals === undefined ? true : opts.internals === true,
  });

  const artifacts = {};
  const roles = { impl: 'implementer', verify: 'verifier', eval: 'evaluator', coord: 'coordinator' };
  for (const key of Object.keys(roles)) {
    const record = cp.registerArtifact({
      name: key + '-artifact',
      roleId: roles[key],
      instructions: 'act as ' + roles[key],
      tools: ['read', 'edit', 'shell'],
      createdBy: 'human-dev',
    });
    cp.bootstrapTrust({ artifactId: record.artifactId, by: 'human-root' });
    artifacts[key] = record;
  }

  const agents = {
    impl: cp.createAgent({ agentId: 'agent-impl', artifactId: artifacts.impl.artifactId, roleId: 'implementer', runtime: { runtimeId: 'rt-1', provider: 'local', model: 'test-model', isolation: 'process' } }),
    verify: cp.createAgent({ agentId: 'agent-verify', artifactId: artifacts.verify.artifactId, roleId: 'verifier' }),
    eval: cp.createAgent({ agentId: 'agent-eval', artifactId: artifacts.eval.artifactId, roleId: 'evaluator' }),
    coord: cp.createAgent({ agentId: 'agent-coord', artifactId: artifacts.coord.artifactId, roleId: 'coordinator' }),
  };

  return { cp, artifacts, agents, clock, calls, spyExecutor };
}

/** Open the three sessions a normal task needs and create the task. */
export async function openWork(world, taskInput) {
  const cp = world.cp;
  const task = cp.createTask(taskInput || { title: 'do work', resources: ['file:src/a.mjs'] });
  const sImpl = await cp.openSession({ agentId: 'agent-impl', taskId: task.taskId });
  const sVerify = await cp.openSession({ agentId: 'agent-verify', taskId: task.taskId, own: false });
  const sCoord = await cp.openSession({ agentId: 'agent-coord', own: false });
  const sEval = await cp.openSession({ agentId: 'agent-eval', own: false });
  return { task, sImpl, sVerify, sCoord, sEval };
}

export function request(session, action, extra) {
  return {
    sessionId: session.sessionId,
    agentId: session.agentId,
    taskId: session.taskId,
    action,
    ...(extra || {}),
  };
}

/** Run the whole happy path and return the ids it produced. */
export async function runHappyPath(world, work) {
  const cp = world.cp;
  const impl = work.sImpl;
  const write = await cp.act(request(impl, 'write', { target: 'file:src/a.mjs', resource: 'file:src/a.mjs', tool: 'edit', params: { content: 'hello' } }));
  const evidence = await cp.produceEvidence({
    sessionId: impl.sessionId, agentId: 'agent-impl', taskId: work.task.taskId, executionId: write.executionId,
    params: { grade: 'E1', command: 'node --test', exitCode: 0, revision: 'rev-1', criterion: 'file exists' },
  });
  const verification = await cp.verify({
    sessionId: work.sVerify.sessionId, agentId: 'agent-verify', taskId: work.task.taskId,
    subjectExecutionId: write.executionId, subjectAgentId: 'agent-impl', verdict: 'PASS',
    criteria: ['file exists'], evidenceIds: [evidence.result.evidenceId],
  });
  const done = await cp.markDone({ sessionId: work.sCoord.sessionId, agentId: 'agent-coord', taskId: work.task.taskId });
  return { write, evidence, verification, done };
}