'use strict';
// Phone-side Frida JS only. PC receiver uses Python sockets, not Frida.
// No game calls, report replacement, evasion, or phone capture-file writes.
const LASERCN_SOCKET_OPTIONS = {
    host: '127.0.0.1', port: 28469, token: "__LOCAL_CAPTURE_TOKEN__",
    enableHooks: true, // false = transport-only diagnosis; no Interceptor.attach calls.
    maxPayloadBytes: 4 * 1024 * 1024,
    maxPendingBytes: 24 * 1024 * 1024,
    flushEveryMs: 250, statusEveryMs: 1500, moduleWaitSeconds: 120
};
const LASERCN_SOCKET_PROFILE = {"package":"com.tencent.tmgp.supercell.brawlstars","version":"69.114.1","librarySha256":"7b643e1c97a9a4a2778b46d0a2e0c3dfd3598f84e36f68f94abfa3dc6bce3aff","targets":[{"id":10100,"direction":"send","vtable":30649632,"typeOffset":20663704,"typeHex":"80ee8452c0035fd6","hookOffset":20663144,"hookHex":"fd7bbea9f30b00f9fd030091f30300aa498bd897619240b9602200913977d597619640b9602200913677d597619a40b9"},{"id":10101,"direction":"send","vtable":30920168,"typeOffset":20663812,"typeHex":"a0ee8452c0035fd6","hookOffset":25845060,"hookHex":"fd7bbea9f30b00f9fd030091f30300aad2c6c497615e40f96022009194b8c197616240f96022009115b1c19761ca40b9"},{"id":12541,"direction":"send","vtable":30924952,"typeOffset":25897336,"typeHex":"a01f8652c0035fd6","hookOffset":25897132,"hookHex":"fd7bbea9f30b00f9fd030091f30300aaf893c4976072029161220091e093bf97680640f9619240b960220091084540f9"},{"id":14049,"direction":"send","vtable":30924792,"typeOffset":25896552,"typeHex":"20dc8652c0035fd6","hookOffset":25896420,"hookHex":"fd7bbea9f30b00f9fd030091f30300aaaa94c497688e40f861220291021140f9e00313aaf30b40f9fd7bc2a840001fd6"},{"id":14358,"direction":"send","vtable":30926872,"typeOffset":25911716,"typeHex":"c0028752c0035fd6","hookOffset":25911584,"hookHex":"fd7bbea9f30b00f9fd030091f30300aadb85c497619240b9602200913c74c197619640b9602200913974c197619a40b9"},{"id":14371,"direction":"send","vtable":30925592,"typeOffset":25902468,"typeHex":"60048752c0035fd6","hookOffset":25902272,"hookHex":"fd7bbea9f30b00f9fd030091f30300aaf38ec4976022009161420291bc78c1976182423960220091487ac19761a640b9"},{"id":20100,"direction":"receive","vtable":29976192,"typeOffset":11629656,"typeHex":"80d08952c0035fd6","hookOffset":11629568,"hookHex":"fd7bbea9f30b00f9fd030091f30300aa2401fb97602200910ceff797e103002a609a00b960220091027d80521beff797"},{"id":20103,"direction":"receive","vtable":30919912,"typeOffset":25844352,"typeHex":"e0d08952c0035fd6","hookOffset":25842448,"hookHex":"ff4301d1fd7b01a9f71300f9f65703a9f44f04a9fd430091f30300aa5dc9c497602200913bb6c19701749752609200b9"},{"id":20104,"direction":"receive","vtable":30920312,"typeOffset":25851792,"typeHex":"00d18952c0035fd6","hookOffset":25850240,"hookHex":"fd7bbca9f70b00f9f65702a9f44f03a9fd030091f30300aac2c1c497602200911fafc197604a00f9602200911cafc197"},{"id":24104,"direction":"receive","vtable":30937784,"typeOffset":26125236,"typeHex":"00c58b52c0035fd6","hookOffset":26125168,"hookHex":"fd7bbea9f30b00f9fd030091f30300aa48b5c397602200917ca4c097609200b96022009179a4c097609600b960220091"},{"id":24124,"direction":"receive","vtable":30925992,"typeOffset":25907852,"typeHex":"80c78b52c0035fd6","hookOffset":25907732,"hookHex":"fd7bbea9f30b00f9fd030091f30300aa9f89c497001280525d1d0f9400e4006f282080521f0800b908900079e87f60b2"},{"id":24131,"direction":"receive","vtable":30927032,"typeOffset":25912624,"typeHex":"60c88b52c0035fd6","hookOffset":25912372,"hookHex":"fd7bbca9f70b00f9f65702a9f44f03a9fd030091f30300aa1585c497602200914974c197609200b9602200914674c197"}],"layout":{"messageStreamOffset":8,"streamLengthOffset":20,"streamCapacityOffset":40,"streamDataOffset":56},"joinCodeUi":{"offset":14904972,"hex":"ff4301d1fd7b02a9f65703a9f44f04a9fd8300915f080071f30300aac00500545f0400710108005469f240f9e8430091"}};

(() => {
    const o = LASERCN_SOCKET_OPTIONS, profile = LASERCN_SOCKET_PROFILE;
    const started = Date.now(), stem = 'lasercn-plain-' + started + '-' + Process.id;
    const state = {phase: 'connecting', pid: Process.id, frames: 0, sentFrames: 0,
        receiverFlushedFrames: 0, errors: 0, skipped: 0, reason: null, lastError: null,
        hookedIds: [], agentVersion: '2026-10-22-socket-v1'};
    const listeners = [], timers = [], binaries = new Map();
    let module = null, connection = null, pending = [], queuedBytes = 0;
    let inFlightBytes = 0, writing = null, accepting = false, failed = false;
    let inputText = '', reader = null;
    const canonical = p => ptr(p).and('0x00ffffffffffffff');
    const notice = s => console.log('[LASERCN SOCKET] ' + s);
    function status() {
        return {...state, updatedAt: new Date().toISOString(), startedAt: new Date(started).toISOString(),
            arch: Process.arch, sessionStem: stem, phoneFilesWritten: false,
            module: module ? {base: module.base.toString(), size: module.size} : null};
    }
    function utf8(text) {
        const bytes = [];
        for (const char of text) {
            const n = char.codePointAt(0);
            if (n < 128) bytes.push(n);
            else if (n < 2048) bytes.push(192 | n >> 6, 128 | n & 63);
            else if (n < 65536) bytes.push(224 | n >> 12, 128 | n >> 6 & 63, 128 | n & 63);
            else bytes.push(240 | n >> 18, 128 | n >> 12 & 63, 128 | n >> 6 & 63, 128 | n & 63);
        }
        return new Uint8Array(bytes).buffer;
    }
    function enqueue(record) {
        if (failed) return false;
        const line = JSON.stringify(record) + '\n', bytes = line.length * 2;
        if (queuedBytes + inFlightBytes + bytes > o.maxPendingBytes) {
            transportFailure('writer-queue-full'); return false;
        }
        pending.push({line, frames: record.kind === 'frame' ? 1 : 0}); queuedBytes += bytes;
        return true;
    }
    async function flush() {
        if (writing) { await writing; return flush(); }
        if (!connection || failed || pending.length === 0) return;
        const batch = pending; pending = []; inFlightBytes = queuedBytes; queuedBytes = 0;
        writing = (async () => {
            // Bound temporary concatenation allocations as well as the persistent queue.
            for (const entry of batch) {
                await connection.output.writeAll(utf8(entry.line));
                state.sentFrames += entry.frames;
            }
        })();
        try { await writing; }
        catch (_) { transportFailure('socket-write-failed'); }
        finally { writing = null; inFlightBytes = 0; }
    }
    function detach() {
        accepting = false;
        for (const timer of timers.splice(0)) clearInterval(timer);
        for (const listener of listeners.splice(0)) {
            try { listener.detach(); } catch (_) { state.errors++; }
        }
    }
    function transportFailure(reason) {
        if (failed || state.phase === 'stopped') return;
        failed = true; detach(); state.phase = 'stopped'; state.reason = reason;
        state.errors++; state.lastError = reason; pending = []; queuedBytes = 0;
        if (connection) connection.close().catch(() => {});
        notice('Stopped: ' + reason + '; receiver files, not sentFrames, prove persistence.');
    }
    async function stop(reason = 'manual-stop') {
        if (failed || state.phase === 'stopped') return status();
        detach(); state.phase = 'stopped'; state.reason = reason;
        enqueue({kind: 'stop', ...status()}); await flush();
        if (connection) await connection.close().catch(() => {});
        return status();
    }
    async function readLine() {
        while (!inputText.includes('\n')) {
            const data = await connection.input.read(4096);
            if (data.byteLength === 0) throw new Error('receiver-disconnected');
            inputText += String.fromCharCode(...new Uint8Array(data));
            if (inputText.length > 16384) throw new Error('invalid-receiver-response');
        }
        const at = inputText.indexOf('\n'), line = inputText.slice(0, at);
        inputText = inputText.slice(at + 1);
        return JSON.parse(line);
    }
    async function receiveAcks() {
        while (!failed && state.phase !== 'stopped') {
            try {
                const ack = await readLine();
                if (ack.kind !== 'ack' || !Number.isSafeInteger(ack.frames) ||
                    ack.frames < state.receiverFlushedFrames || ack.frames > state.frames) {
                    throw new Error('invalid-receiver-ack');
                }
                state.receiverFlushedFrames = ack.frames;
            } catch (_) {
                if (state.phase !== 'stopped') transportFailure('receiver-disconnected-or-rejected');
                return;
            }
        }
    }
    function readable(address, size) {
        address = canonical(address);
        if (!Number.isSafeInteger(size) || size < 0 || size > o.maxPayloadBytes) throw new Error('invalid-memory-length');
        if (size === 0) return new ArrayBuffer(0);
        const range = Process.findRangeByAddress(address);
        if (address.isNull() || !range || !range.protection.includes('r') ||
            address.add(size).compare(range.base.add(range.size)) > 0) throw new Error('unreadable-memory-span');
        const bytes = address.readVolatile(size);
        if (bytes === null || bytes.byteLength !== size) throw new Error('short-memory-read');
        return bytes;
    }
    const view = (p, n) => new DataView(readable(p, n));
    const pointer = (data, offset) => canonical('0x' + data.getBigUint64(offset, true).toString(16));
    function hex(buffer) {
        let text = '';
        for (const b of new Uint8Array(buffer)) text += b.toString(16).padStart(2, '0');
        return text;
    }
    function checkBytes(offset, expected) {
        if (offset < 0 || offset + expected.length / 2 > module.size ||
            hex(readable(module.base.add(offset), expected.length / 2)) !== expected) {
            throw new Error('fingerprint-mismatch-at-0x' + offset.toString(16));
        }
    }
    function capture(message, spec) {
        if (!accepting) return;
        try {
            message = canonical(message);
            const header = view(message, 144), l = profile.layout;
            if (!pointer(header, 0).equals(module.base.add(spec.vtable))) { state.skipped++; return; }
            const stream = view(message.add(l.messageStreamOffset), 64);
            const cursor = stream.getUint32(l.streamLengthOffset, true);
            const length = spec.direction === 'send' ? cursor : stream.getUint32(24, true);
            if (length > o.maxPayloadBytes || length > stream.getUint32(l.streamCapacityOffset, true) ||
                (spec.direction === 'receive' && cursor !== 0)) throw new Error('invalid-stream-bounds');
            const snapshot = readable(pointer(stream, l.streamDataOffset), length);
            const version = header.getUint32(136, true);
            if (version > 65535) throw new Error('invalid-wire-version');
            const direction = spec.direction === 'send' ? 'c2s' : 's2c';
            const binaryFile = stem + '-' + direction + '-' + spec.id + '.bin';
            const offset = binaries.get(binaryFile) || 0;
            if (!enqueue({kind: 'frame', sequence: state.frames + 1, time: new Date().toISOString(),
                direction, id: spec.id, version, stage: spec.direction === 'send' ? 'after-encode' : 'before-decode',
                length, bodyHex: hex(snapshot), binaryFile, binaryOffset: offset, binaryLength: 7 + length})) return;
            binaries.set(binaryFile, offset + 7 + length); state.frames++;
        } catch (error) {
            state.errors++; state.lastError = String(error.message || error).slice(0, 200);
            if (state.errors >= 8) stop('repeated-invalid-stream');
        }
    }
    async function install(found) {
        state.phase = 'checking'; module = found;
        enqueue({kind: 'status', ...status()}); await flush();
        if (failed) return;
        try {
            const processName = File.readAllText('/proc/self/cmdline').split('\x00')[0];
            if (processName !== profile.package) throw new Error('wrong-target-process');
            for (const spec of profile.targets) {
                checkBytes(spec.hookOffset, spec.hookHex); checkBytes(spec.typeOffset, spec.typeHex);
                const table = view(module.base.add(spec.vtable), 48);
                if (!pointer(table, spec.direction === 'send' ? 16 : 24).equals(module.base.add(spec.hookOffset)) ||
                    !pointer(table, 40).equals(module.base.add(spec.typeOffset))) throw new Error('vtable-mismatch-' + spec.id);
                const range = Process.findRangeByAddress(module.base.add(spec.hookOffset));
                if (!range || !range.protection.includes('x')) throw new Error('codec-not-executable-' + spec.id);
            }
            for (const spec of profile.targets) {
                enqueue({kind: 'event', event: 'before-hook', id: spec.id}); await flush();
                if (failed || state.phase === 'stopped') return;
                listeners.push(Interceptor.attach(module.base.add(spec.hookOffset), spec.direction === 'send' ? {
                    onEnter(args) { this.lasercnMessage = args[0]; },
                    onLeave() { capture(this.lasercnMessage, spec); }
                } : {onEnter(args) { capture(args[0], spec); }}));
                state.hookedIds.push(spec.id);
            }
            state.phase = 'capturing'; accepting = true;
            enqueue({kind: 'status', ...status()}); await flush();
            notice('READY: receiver connected, hooks installed; no phone capture files.');
        } catch (error) {
            state.lastError = String(error.message || error).slice(0, 200);
            await stop('initialization-failed');
        }
    }
    async function poll() {
        if (state.phase !== 'waiting') return;
        try {
            const found = Process.findModuleByName('libg.so');
            if (found) await install(found);
            else if (Date.now() - started > o.moduleWaitSeconds * 1000) await stop('libg-not-loaded');
        } catch (error) {
            state.lastError = String(error.message || error).slice(0, 200);
            await stop('module-discovery-failed');
        }
    }
    const api = {status, stop, mark(text) {
        enqueue({kind: 'event', event: String(text).slice(0, 100)}); return status();
    }};
    globalThis.LaserCnCapture = api;
    if (typeof rpc !== 'undefined') rpc.exports = api;
    async function start() {
        // No hooks unless the computer has authenticated and acknowledged the connection.
        try {
            let timedOut = false;
            const timeout = setTimeout(() => { timedOut = true; transportFailure('receiver-connect-timeout'); }, 10000);
            try {
                connection = await Socket.connect({host: o.host, port: o.port});
                if (timedOut) { await connection.close(); return; }
                await connection.output.writeAll(utf8(JSON.stringify({kind: 'hello', protocol: 'lasercn-jsonl-v1',
                    token: o.token, sessionStem: stem, pid: Process.id}) + '\n'));
                const reply = await readLine();
                if (reply.kind !== 'ready' || reply.protocol !== 'lasercn-jsonl-v1') throw new Error('receiver-auth-failed');
            } finally { clearTimeout(timeout); }
            if (failed) return;
            enqueue({kind: 'session', ...status(), package: profile.package, profileVersion: profile.version,
                expectedLibrarySha256: profile.librarySha256, fullFileHashCheckedByAgent: false,
                outputFormats: ['jsonl', 'bin'], packetCountLimit: null});
            await flush();
            reader = receiveAcks();
            if (Process.arch !== 'arm64' || Process.pointerSize !== 8) { await stop('wrong-architecture'); return; }
            if (o.enableHooks === false) {
                state.phase = 'transport-only';
                enqueue({kind: 'status', ...status()}); await flush();
            } else state.phase = 'waiting';
            timers.push(setInterval(() => { flush(); }, o.flushEveryMs));
            timers.push(setInterval(() => { enqueue({kind: 'status', ...status()}); flush(); }, o.statusEveryMs));
            if (o.enableHooks !== false) { timers.push(setInterval(poll, 100)); await poll(); }
        } catch (_) { transportFailure('receiver-connect-or-auth-failed'); }
    }
    start();
})();
