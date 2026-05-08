import Foundation
import EndpointSecurity

private let ecEventTypesMain: Set<String> = [
    "access", "authentication",
    "authorization_judgement", "authorization_petition",
    "btm_launch_item_add", "btm_launch_item_remove",
    "create",
    "cs_invalidated", "deleteextattr",
    "exec", "exit",
    "file_provider_update", "fork",
    "getextattr", "iokit_open",
    "login_login", "login_logout",
    "lw_session_login", "lw_session_logout",
    "lw_session_unlock", "mmap",
    "mount", "mprotect",
    "openssh_login", "openssh_logout",
    "profile_add", "profile_remove",
    "remote_thread_create", "remount",
    "rename", "screensharing_attach",
    "su", "sudo",
    "trace", "truncate",
    "xp_malware_detected", "xp_malware_remediated",
    "xpc_connect"
]

private let ecEventTypesExtra: Set<String> = [
    "chdir", "chroot",
    "clone", "close",
    "copyfile",
    "fcntl", "file_provider_materialize",
    "fsgetpath", "get_task",
    "get_task_inspect", "get_task_name",
    "get_task_read", "getattrlist",
    "link", "listextattr",
    "lookup", "lw_session_lock",
    "od_modify_password", "open",
    "proc_check", "proc_suspend_resume",
    "pty_close", "pty_grant",
    "readdir", "readlink",
    "screensharing_detach", "searchfs",
    "setacl", "setattrlist",
    "setegid", "seteuid",
    "setextattr", "setflags",
    "setgid", "setmode",
    "setowner", "setregid",
    "setreuid", "setuid",
    "signal", "stat",
    "uipc_bind", "uipc_connect",
    "unlink", "unmount",
    "utimes", "write"
]

private let ecEventTypesRare: Set<String> = [
    "dup", "exchangedata",
    "od_attribute_set", "od_attribute_value_add",
    "od_attribute_value_remove", "od_create_group",
    "od_create_user", "od_delete_group",
    "od_delete_user", "od_disable_user",
    "od_enable_user", "od_group_add",
    "od_group_remove", "od_group_set",
    "kextload", "kextunload"
]

let eventNameToType: [String: es_event_type_t] = [
    "access": ES_EVENT_TYPE_NOTIFY_ACCESS,
    "authentication": ES_EVENT_TYPE_NOTIFY_AUTHENTICATION,
    "authorization_judgement": ES_EVENT_TYPE_NOTIFY_AUTHORIZATION_JUDGEMENT,
    "authorization_petition": ES_EVENT_TYPE_NOTIFY_AUTHORIZATION_PETITION,
    "btm_launch_item_add": ES_EVENT_TYPE_NOTIFY_BTM_LAUNCH_ITEM_ADD,
    "btm_launch_item_remove": ES_EVENT_TYPE_NOTIFY_BTM_LAUNCH_ITEM_REMOVE,
    "create": ES_EVENT_TYPE_NOTIFY_CREATE,
    "cs_invalidated": ES_EVENT_TYPE_NOTIFY_CS_INVALIDATED,
    "deleteextattr": ES_EVENT_TYPE_NOTIFY_DELETEEXTATTR,
    "exec": ES_EVENT_TYPE_NOTIFY_EXEC,
    "exit": ES_EVENT_TYPE_NOTIFY_EXIT,
    "file_provider_update": ES_EVENT_TYPE_NOTIFY_FILE_PROVIDER_UPDATE,
    "fork": ES_EVENT_TYPE_NOTIFY_FORK,
    "getextattr": ES_EVENT_TYPE_NOTIFY_GETEXTATTR,
    "iokit_open": ES_EVENT_TYPE_NOTIFY_IOKIT_OPEN,
    "login_login": ES_EVENT_TYPE_NOTIFY_LOGIN_LOGIN,
    "login_logout": ES_EVENT_TYPE_NOTIFY_LOGIN_LOGOUT,
    "lw_session_login": ES_EVENT_TYPE_NOTIFY_LW_SESSION_LOGIN,
    "lw_session_logout": ES_EVENT_TYPE_NOTIFY_LW_SESSION_LOGOUT,
    "lw_session_unlock": ES_EVENT_TYPE_NOTIFY_LW_SESSION_UNLOCK,
    "mmap": ES_EVENT_TYPE_NOTIFY_MMAP,
    "mount": ES_EVENT_TYPE_NOTIFY_MOUNT,
    "mprotect": ES_EVENT_TYPE_NOTIFY_MPROTECT,
    "openssh_login": ES_EVENT_TYPE_NOTIFY_OPENSSH_LOGIN,
    "openssh_logout": ES_EVENT_TYPE_NOTIFY_OPENSSH_LOGOUT,
    "profile_add": ES_EVENT_TYPE_NOTIFY_PROFILE_ADD,
    "profile_remove": ES_EVENT_TYPE_NOTIFY_PROFILE_REMOVE,
    "remote_thread_create": ES_EVENT_TYPE_NOTIFY_REMOTE_THREAD_CREATE,
    "remount": ES_EVENT_TYPE_NOTIFY_REMOUNT,
    "rename": ES_EVENT_TYPE_NOTIFY_RENAME,
    "screensharing_attach": ES_EVENT_TYPE_NOTIFY_SCREENSHARING_ATTACH,
    "su": ES_EVENT_TYPE_NOTIFY_SU,
    "sudo": ES_EVENT_TYPE_NOTIFY_SUDO,
    "trace": ES_EVENT_TYPE_NOTIFY_TRACE,
    "truncate": ES_EVENT_TYPE_NOTIFY_TRUNCATE,
    "xp_malware_detected": ES_EVENT_TYPE_NOTIFY_XP_MALWARE_DETECTED,
    "xp_malware_remediated": ES_EVENT_TYPE_NOTIFY_XP_MALWARE_REMEDIATED,
    "xpc_connect": ES_EVENT_TYPE_NOTIFY_XPC_CONNECT,
    "chdir": ES_EVENT_TYPE_NOTIFY_CHDIR,
    "chroot": ES_EVENT_TYPE_NOTIFY_CHROOT,
    "clone": ES_EVENT_TYPE_NOTIFY_CLONE,
    "close": ES_EVENT_TYPE_NOTIFY_CLOSE,
    "copyfile": ES_EVENT_TYPE_NOTIFY_COPYFILE,
    "fcntl": ES_EVENT_TYPE_NOTIFY_FCNTL,
    "file_provider_materialize": ES_EVENT_TYPE_NOTIFY_FILE_PROVIDER_MATERIALIZE,
    "fsgetpath": ES_EVENT_TYPE_NOTIFY_FSGETPATH,
    "get_task": ES_EVENT_TYPE_NOTIFY_GET_TASK,
    "get_task_inspect": ES_EVENT_TYPE_NOTIFY_GET_TASK_INSPECT,
    "get_task_name": ES_EVENT_TYPE_NOTIFY_GET_TASK_NAME,
    "get_task_read": ES_EVENT_TYPE_NOTIFY_GET_TASK_READ,
    "getattrlist": ES_EVENT_TYPE_NOTIFY_GETATTRLIST,
    "link": ES_EVENT_TYPE_NOTIFY_LINK,
    "listextattr": ES_EVENT_TYPE_NOTIFY_LISTEXTATTR,
    "lookup": ES_EVENT_TYPE_NOTIFY_LOOKUP,
    "lw_session_lock": ES_EVENT_TYPE_NOTIFY_LW_SESSION_LOCK,
    "od_modify_password": ES_EVENT_TYPE_NOTIFY_OD_MODIFY_PASSWORD,
    "open": ES_EVENT_TYPE_NOTIFY_OPEN,
    "proc_check": ES_EVENT_TYPE_NOTIFY_PROC_CHECK,
    "proc_suspend_resume": ES_EVENT_TYPE_NOTIFY_PROC_SUSPEND_RESUME,
    "pty_close": ES_EVENT_TYPE_NOTIFY_PTY_CLOSE,
    "pty_grant": ES_EVENT_TYPE_NOTIFY_PTY_GRANT,
    "readdir": ES_EVENT_TYPE_NOTIFY_READDIR,
    "readlink": ES_EVENT_TYPE_NOTIFY_READLINK,
    "screensharing_detach": ES_EVENT_TYPE_NOTIFY_SCREENSHARING_DETACH,
    "searchfs": ES_EVENT_TYPE_NOTIFY_SEARCHFS,
    "setacl": ES_EVENT_TYPE_NOTIFY_SETACL,
    "setattrlist": ES_EVENT_TYPE_NOTIFY_SETATTRLIST,
    "setegid": ES_EVENT_TYPE_NOTIFY_SETEGID,
    "seteuid": ES_EVENT_TYPE_NOTIFY_SETEUID,
    "setextattr": ES_EVENT_TYPE_NOTIFY_SETEXTATTR,
    "setflags": ES_EVENT_TYPE_NOTIFY_SETFLAGS,
    "setgid": ES_EVENT_TYPE_NOTIFY_SETGID,
    "setmode": ES_EVENT_TYPE_NOTIFY_SETMODE,
    "setowner": ES_EVENT_TYPE_NOTIFY_SETOWNER,
    "setregid": ES_EVENT_TYPE_NOTIFY_SETREGID,
    "setreuid": ES_EVENT_TYPE_NOTIFY_SETREUID,
    "setuid": ES_EVENT_TYPE_NOTIFY_SETUID,
    "signal": ES_EVENT_TYPE_NOTIFY_SIGNAL,
    "stat": ES_EVENT_TYPE_NOTIFY_STAT,
    "uipc_bind": ES_EVENT_TYPE_NOTIFY_UIPC_BIND,
    "uipc_connect": ES_EVENT_TYPE_NOTIFY_UIPC_CONNECT,
    "unlink": ES_EVENT_TYPE_NOTIFY_UNLINK,
    "unmount": ES_EVENT_TYPE_NOTIFY_UNMOUNT,
    "utimes": ES_EVENT_TYPE_NOTIFY_UTIMES,
    "write": ES_EVENT_TYPE_NOTIFY_WRITE,
    "dup": ES_EVENT_TYPE_NOTIFY_DUP,
    "exchangedata": ES_EVENT_TYPE_NOTIFY_EXCHANGEDATA,
    "od_attribute_set": ES_EVENT_TYPE_NOTIFY_OD_ATTRIBUTE_SET,
    "od_attribute_value_add": ES_EVENT_TYPE_NOTIFY_OD_ATTRIBUTE_VALUE_ADD,
    "od_attribute_value_remove": ES_EVENT_TYPE_NOTIFY_OD_ATTRIBUTE_VALUE_REMOVE,
    "od_create_group": ES_EVENT_TYPE_NOTIFY_OD_CREATE_GROUP,
    "od_create_user": ES_EVENT_TYPE_NOTIFY_OD_CREATE_USER,
    "od_delete_group": ES_EVENT_TYPE_NOTIFY_OD_DELETE_GROUP,
    "od_delete_user": ES_EVENT_TYPE_NOTIFY_OD_DELETE_USER,
    "od_disable_user": ES_EVENT_TYPE_NOTIFY_OD_DISABLE_USER,
    "od_enable_user": ES_EVENT_TYPE_NOTIFY_OD_ENABLE_USER,
    "od_group_add": ES_EVENT_TYPE_NOTIFY_OD_GROUP_ADD,
    "od_group_remove": ES_EVENT_TYPE_NOTIFY_OD_GROUP_REMOVE,
    "od_group_set": ES_EVENT_TYPE_NOTIFY_OD_GROUP_SET,
    "kextload": ES_EVENT_TYPE_NOTIFY_KEXTLOAD,
    "kextunload": ES_EVENT_TYPE_NOTIFY_KEXTUNLOAD,
]

let eventTypeToName: [es_event_type_t: String] = {
    var reversed: [es_event_type_t: String] = [:]
    for (name, type) in eventNameToType {
        reversed[type] = name
    }
    return reversed
}()

func resolveEventTypes(from names: Set<String>) -> [es_event_type_t] {
    return names.compactMap { eventNameToType[$0] }
}

private func extractProcessInfo(_ process: UnsafePointer<es_process_t>) -> [String: Any] {
    var info: [String: Any] = [:]
    let p = process.pointee

    info["pid"] = Int(audit_token_to_pid(p.audit_token))
    info["ppid"] = Int(p.ppid)
    info["original_ppid"] = Int(p.original_ppid)
    info["group_id"] = Int(p.group_id)
    info["session_id"] = Int(p.session_id)
    info["executable_path"] = String(cString: p.executable.pointee.path.data)
    info["is_platform_binary"] = Bool(p.is_platform_binary)
    info["is_es_client"] = Bool(p.is_es_client)
    info["codesigning_flags"] = Int(p.codesigning_flags)
    info["signing_id"] = String(cString: p.signing_id.data)

    if let teamData = p.team_id.data {
        info["team_id"] = String(cString: teamData)
    }

    let cdhash = p.cdhash
    let cdhashHex = withUnsafeBytes(of: cdhash) { bytes in
        bytes.prefix(20).map { String(format: "%02x", $0) }.joined()
    }
    info["cdhash"] = cdhashHex

    return info
}

private func extractFileInfo(_ file: UnsafePointer<es_file_t>) -> [String: Any] {
    return [
        "path": String(cString: file.pointee.path.data),
        "path_truncated": Bool(file.pointee.path_truncated)
    ]
}

private func formatTimestamp(_ ts: timespec) -> String {
    let millis = Int64(ts.tv_sec) * 1000 + Int64(ts.tv_nsec) / 1_000_000
    return String(millis)
}

private func formatTimeval(_ tv: timeval) -> String {
    let millis = Int64(tv.tv_sec) * 1000 + Int64(tv.tv_usec) / 1000
    return String(millis)
}

private func parseExecArguments(_ event: inout es_event_exec_t) -> [String] {
    var args: [String] = []
    let argc = es_exec_arg_count(&event)
    for i in 0..<argc {
        args.append(String(cString: es_exec_arg(&event, i).data))
    }
    return args
}

// WIP
private func parseExecEnv(_ event: inout es_event_exec_t) -> [String] {
    var envs: [String] = []
    let envc = es_exec_env_count(&event)
    for i in 0..<envc {
        envs.append(String(cString: es_exec_env(&event, i).data))
    }
    return envs
}

private func jsonSafe(_ value: Any) -> Any {
    switch value {
    case let b as ObjCBool: return b.boolValue
    case let u as UInt32: return Int(u)
    case let u as UInt64: return Int(u)
    case let u as UInt: return Int(u)
    case let i as Int32: return Int(i)
    default: return value
    }
}

private func serializeMessage(_ message: UnsafePointer<es_message_t>) -> [String: Any]? {
    let msg = message.pointee
    let eventType = msg.event_type

    guard let eventName = eventTypeToName[eventType] else { return nil }

    var result: [String: Any] = [:]
    result["event_type"] = eventName
    result["timestamp"] = formatTimestamp(msg.time)
    result["global_seq_num"] = Int(msg.global_seq_num)
    result["process"] = extractProcessInfo(msg.process)

    var eventData: [String: Any] = [:]

    switch eventType {

    case ES_EVENT_TYPE_NOTIFY_EXEC:
        var execEvent = msg.event.exec
        eventData["target"] = extractProcessInfo(execEvent.target)
        eventData["args"] = parseExecArguments(&execEvent)
        if let script = execEvent.script {
            eventData["script"] = extractFileInfo(script)
        }

    case ES_EVENT_TYPE_NOTIFY_EXIT:
        eventData["status"] = Int(msg.event.exit.stat)

    case ES_EVENT_TYPE_NOTIFY_FORK:
        eventData["child"] = extractProcessInfo(msg.event.fork.child)

    case ES_EVENT_TYPE_NOTIFY_CREATE:
        let createEvent = msg.event.create
        if createEvent.destination_type == ES_DESTINATION_TYPE_NEW_PATH {
            let dir = String(cString: createEvent.destination.new_path.dir.pointee.path.data)
            let filename = String(cString: createEvent.destination.new_path.filename.data)
            eventData["destination_type"] = "new_path"
            eventData["directory"] = dir
            eventData["filename"] = filename
        } else {
            eventData["destination_type"] = "existing_file"
            eventData["file"] = extractFileInfo(createEvent.destination.existing_file)
        }

    case ES_EVENT_TYPE_NOTIFY_OPEN:
        eventData["file"] = extractFileInfo(msg.event.open.file)
        eventData["fflag"] = Int(msg.event.open.fflag)

    case ES_EVENT_TYPE_NOTIFY_CLOSE:
        eventData["target"] = extractFileInfo(msg.event.close.target)
        eventData["modified"] = Bool(msg.event.close.modified)

    case ES_EVENT_TYPE_NOTIFY_WRITE:
        eventData["target"] = extractFileInfo(msg.event.write.target)

    case ES_EVENT_TYPE_NOTIFY_RENAME:
        let renameEvent = msg.event.rename
        eventData["source"] = extractFileInfo(renameEvent.source)
        if renameEvent.destination_type == ES_DESTINATION_TYPE_NEW_PATH {
            let dir = String(cString: renameEvent.destination.new_path.dir.pointee.path.data)
            let filename = String(cString: renameEvent.destination.new_path.filename.data)
            eventData["destination_type"] = "new_path"
            eventData["destination_dir"] = dir
            eventData["destination_filename"] = filename
        } else {
            eventData["destination_type"] = "existing_file"
            eventData["destination_file"] = extractFileInfo(renameEvent.destination.existing_file)
        }

    case ES_EVENT_TYPE_NOTIFY_UNLINK:
        eventData["target"] = extractFileInfo(msg.event.unlink.target)
        eventData["parent_dir"] = extractFileInfo(msg.event.unlink.parent_dir)

    case ES_EVENT_TYPE_NOTIFY_LINK:
        eventData["source"] = extractFileInfo(msg.event.link.source)
        eventData["target_dir"] = extractFileInfo(msg.event.link.target_dir)
        eventData["target_filename"] = String(cString: msg.event.link.target_filename.data)

    case ES_EVENT_TYPE_NOTIFY_MMAP:
        eventData["source"] = extractFileInfo(msg.event.mmap.source)
        eventData["flags"] = Int(msg.event.mmap.flags)
        eventData["protection"] = Int(msg.event.mmap.protection)

    case ES_EVENT_TYPE_NOTIFY_MPROTECT:
        eventData["protection"] = Int(msg.event.mprotect.protection)

    case ES_EVENT_TYPE_NOTIFY_MOUNT, ES_EVENT_TYPE_NOTIFY_REMOUNT:
        let statfs = msg.event.mount.statfs.pointee
        eventData["mount_point"] = withUnsafePointer(to: statfs.f_mntonname) { ptr in
            ptr.withMemoryRebound(to: CChar.self, capacity: Int(MAXPATHLEN)) {
                String(cString: $0)
            }
        }
        eventData["fs_type"] = withUnsafePointer(to: statfs.f_fstypename) { ptr in
            ptr.withMemoryRebound(to: CChar.self, capacity: Int(MFSTYPENAMELEN)) {
                String(cString: $0)
            }
        }

    case ES_EVENT_TYPE_NOTIFY_UNMOUNT:
        let statfs = msg.event.unmount.statfs.pointee
        eventData["mount_point"] = withUnsafePointer(to: statfs.f_mntonname) { ptr in
            ptr.withMemoryRebound(to: CChar.self, capacity: Int(MAXPATHLEN)) {
                String(cString: $0)
            }
        }

    case ES_EVENT_TYPE_NOTIFY_ACCESS:
        eventData["target"] = extractFileInfo(msg.event.access.target)
        eventData["mode"] = Int(msg.event.access.mode)

    case ES_EVENT_TYPE_NOTIFY_TRUNCATE:
        eventData["target"] = extractFileInfo(msg.event.truncate.target)

    case ES_EVENT_TYPE_NOTIFY_CHDIR:
        eventData["target"] = extractFileInfo(msg.event.chdir.target)

    case ES_EVENT_TYPE_NOTIFY_CHROOT:
        eventData["target"] = extractFileInfo(msg.event.chroot.target)

    case ES_EVENT_TYPE_NOTIFY_STAT:
        eventData["target"] = extractFileInfo(msg.event.stat.target)

    case ES_EVENT_TYPE_NOTIFY_READDIR:
        eventData["target"] = extractFileInfo(msg.event.readdir.target)

    case ES_EVENT_TYPE_NOTIFY_READLINK:
        eventData["source"] = extractFileInfo(msg.event.readlink.source)

    case ES_EVENT_TYPE_NOTIFY_LOOKUP:
        eventData["source_dir"] = extractFileInfo(msg.event.lookup.source_dir)
        eventData["relative_target"] = String(cString: msg.event.lookup.relative_target.data)

    case ES_EVENT_TYPE_NOTIFY_CLONE:
        eventData["source"] = extractFileInfo(msg.event.clone.source)
        eventData["target_dir"] = extractFileInfo(msg.event.clone.target_dir)
        eventData["target_name"] = String(cString: msg.event.clone.target_name.data)

    case ES_EVENT_TYPE_NOTIFY_COPYFILE:
        eventData["source"] = extractFileInfo(msg.event.copyfile.source)
        if let targetFile = msg.event.copyfile.target_file {
            eventData["target_file"] = extractFileInfo(targetFile)
        }
        eventData["target_dir"] = extractFileInfo(msg.event.copyfile.target_dir)
        eventData["target_name"] = String(cString: msg.event.copyfile.target_name.data)
        eventData["mode"] = Int(msg.event.copyfile.mode)
        eventData["flags"] = Int(msg.event.copyfile.flags)

    case ES_EVENT_TYPE_NOTIFY_EXCHANGEDATA:
        eventData["file1"] = extractFileInfo(msg.event.exchangedata.file1)
        eventData["file2"] = extractFileInfo(msg.event.exchangedata.file2)

    case ES_EVENT_TYPE_NOTIFY_FCNTL:
        eventData["target"] = extractFileInfo(msg.event.fcntl.target)
        eventData["cmd"] = Int(msg.event.fcntl.cmd)

    case ES_EVENT_TYPE_NOTIFY_FSGETPATH:
        eventData["target"] = extractFileInfo(msg.event.fsgetpath.target)

    case ES_EVENT_TYPE_NOTIFY_DUP:
        eventData["target"] = extractFileInfo(msg.event.dup.target)

    case ES_EVENT_TYPE_NOTIFY_GETATTRLIST:
        eventData["target"] = extractFileInfo(msg.event.getattrlist.target)

    case ES_EVENT_TYPE_NOTIFY_SETATTRLIST:
        eventData["target"] = extractFileInfo(msg.event.setattrlist.target)

    case ES_EVENT_TYPE_NOTIFY_SEARCHFS:
        eventData["target"] = extractFileInfo(msg.event.searchfs.target)

    case ES_EVENT_TYPE_NOTIFY_DELETEEXTATTR:
        eventData["target"] = extractFileInfo(msg.event.deleteextattr.target)
        eventData["extattr"] = String(cString: msg.event.deleteextattr.extattr.data)

    case ES_EVENT_TYPE_NOTIFY_GETEXTATTR:
        eventData["target"] = extractFileInfo(msg.event.getextattr.target)
        eventData["extattr"] = String(cString: msg.event.getextattr.extattr.data)

    case ES_EVENT_TYPE_NOTIFY_SETEXTATTR:
        eventData["target"] = extractFileInfo(msg.event.setextattr.target)
        eventData["extattr"] = String(cString: msg.event.setextattr.extattr.data)

    case ES_EVENT_TYPE_NOTIFY_LISTEXTATTR:
        eventData["target"] = extractFileInfo(msg.event.listextattr.target)

    case ES_EVENT_TYPE_NOTIFY_SETFLAGS:
        eventData["target"] = extractFileInfo(msg.event.setflags.target)
        eventData["flags"] = Int(msg.event.setflags.flags)

    case ES_EVENT_TYPE_NOTIFY_SETMODE:
        eventData["target"] = extractFileInfo(msg.event.setmode.target)
        eventData["mode"] = Int(msg.event.setmode.mode)

    case ES_EVENT_TYPE_NOTIFY_SETOWNER:
        eventData["target"] = extractFileInfo(msg.event.setowner.target)
        eventData["uid"] = Int(msg.event.setowner.uid)
        eventData["gid"] = Int(msg.event.setowner.gid)

    case ES_EVENT_TYPE_NOTIFY_SETACL:
        eventData["target"] = extractFileInfo(msg.event.setacl.target)

    case ES_EVENT_TYPE_NOTIFY_UTIMES:
        eventData["target"] = extractFileInfo(msg.event.utimes.target)

    case ES_EVENT_TYPE_NOTIFY_SIGNAL:
        eventData["sig"] = Int(msg.event.signal.sig)
        eventData["target"] = extractProcessInfo(msg.event.signal.target)

    case ES_EVENT_TYPE_NOTIFY_TRACE:
        eventData["target"] = extractProcessInfo(msg.event.trace.target)

    case ES_EVENT_TYPE_NOTIFY_IOKIT_OPEN:
        eventData["user_client_type"] = Int(msg.event.iokit_open.user_client_type)
        eventData["user_client_class"] = String(cString: msg.event.iokit_open.user_client_class.data)

    case ES_EVENT_TYPE_NOTIFY_GET_TASK:
        eventData["target"] = extractProcessInfo(msg.event.get_task.target)
    case ES_EVENT_TYPE_NOTIFY_GET_TASK_INSPECT:
        eventData["target"] = extractProcessInfo(msg.event.get_task_inspect.target)
    case ES_EVENT_TYPE_NOTIFY_GET_TASK_READ:
        eventData["target"] = extractProcessInfo(msg.event.get_task_read.target)
    case ES_EVENT_TYPE_NOTIFY_GET_TASK_NAME:
        eventData["target"] = extractProcessInfo(msg.event.get_task_name.target)

    case ES_EVENT_TYPE_NOTIFY_PROC_CHECK:
        if let target = msg.event.proc_check.target {
            eventData["target"] = extractProcessInfo(target)
        }
        eventData["type"] = Int(msg.event.proc_check.type.rawValue)
        eventData["flavor"] = Int(msg.event.proc_check.flavor)

    case ES_EVENT_TYPE_NOTIFY_PROC_SUSPEND_RESUME:
        if let target = msg.event.proc_suspend_resume.target {
            eventData["target"] = extractProcessInfo(target)
        }
        eventData["type"] = Int(msg.event.proc_suspend_resume.type.rawValue)

    case ES_EVENT_TYPE_NOTIFY_REMOTE_THREAD_CREATE:
        eventData["target"] = extractProcessInfo(msg.event.remote_thread_create.target)

    case ES_EVENT_TYPE_NOTIFY_CS_INVALIDATED:
        break

    case ES_EVENT_TYPE_NOTIFY_PTY_GRANT:
        eventData["dev"] = Int(msg.event.pty_grant.dev)
    case ES_EVENT_TYPE_NOTIFY_PTY_CLOSE:
        eventData["dev"] = Int(msg.event.pty_close.dev)

    case ES_EVENT_TYPE_NOTIFY_UIPC_BIND:
        eventData["dir"] = extractFileInfo(msg.event.uipc_bind.dir)
        eventData["filename"] = String(cString: msg.event.uipc_bind.filename.data)

    case ES_EVENT_TYPE_NOTIFY_UIPC_CONNECT:
        eventData["file"] = extractFileInfo(msg.event.uipc_connect.file)
        eventData["domain"] = Int(msg.event.uipc_connect.domain)
        eventData["type"] = Int(msg.event.uipc_connect.type)
        eventData["protocol"] = Int(msg.event.uipc_connect.protocol)

    case ES_EVENT_TYPE_NOTIFY_XPC_CONNECT:
        let xpcEvent = msg.event.xpc_connect.pointee
        eventData["service_name"] = String(cString: xpcEvent.service_name.data)
        eventData["service_domain_type"] = Int(xpcEvent.service_domain_type.rawValue)

    case ES_EVENT_TYPE_NOTIFY_FILE_PROVIDER_MATERIALIZE:
        if let instigator = msg.event.file_provider_materialize.instigator {
            eventData["instigator"] = extractProcessInfo(instigator)
        }
        eventData["source"] = extractFileInfo(msg.event.file_provider_materialize.source)
        eventData["target"] = extractFileInfo(msg.event.file_provider_materialize.target)

    case ES_EVENT_TYPE_NOTIFY_FILE_PROVIDER_UPDATE:
        eventData["source"] = extractFileInfo(msg.event.file_provider_update.source)
        eventData["target_path"] = String(cString: msg.event.file_provider_update.target_path.data)

    case ES_EVENT_TYPE_NOTIFY_SETUID:
        eventData["uid"] = Int(msg.event.setuid.uid)
    case ES_EVENT_TYPE_NOTIFY_SETEUID:
        eventData["euid"] = Int(msg.event.seteuid.euid)
    case ES_EVENT_TYPE_NOTIFY_SETGID:
        eventData["gid"] = Int(msg.event.setgid.gid)
    case ES_EVENT_TYPE_NOTIFY_SETEGID:
        eventData["egid"] = Int(msg.event.setegid.egid)
    case ES_EVENT_TYPE_NOTIFY_SETREUID:
        eventData["ruid"] = Int(msg.event.setreuid.ruid)
        eventData["euid"] = Int(msg.event.setreuid.euid)
    case ES_EVENT_TYPE_NOTIFY_SETREGID:
        eventData["rgid"] = Int(msg.event.setregid.rgid)
        eventData["egid"] = Int(msg.event.setregid.egid)

    case ES_EVENT_TYPE_NOTIFY_KEXTLOAD:
        eventData["identifier"] = String(cString: msg.event.kextload.identifier.data)
    case ES_EVENT_TYPE_NOTIFY_KEXTUNLOAD:
        eventData["identifier"] = String(cString: msg.event.kextunload.identifier.data)

    case ES_EVENT_TYPE_NOTIFY_LOGIN_LOGIN:
        let e = msg.event.login_login.pointee
        eventData["success"] = Bool(e.success)
        eventData["failure_message"] = String(cString: e.failure_message.data)
        eventData["username"] = String(cString: e.username.data)
    case ES_EVENT_TYPE_NOTIFY_LOGIN_LOGOUT:
        let e = msg.event.login_logout.pointee
        eventData["username"] = String(cString: e.username.data)
    case ES_EVENT_TYPE_NOTIFY_LW_SESSION_LOGIN:
        let e = msg.event.lw_session_login.pointee
        eventData["username"] = String(cString: e.username.data)
        eventData["graphical_session_id"] = Int(e.graphical_session_id)
    case ES_EVENT_TYPE_NOTIFY_LW_SESSION_LOGOUT:
        let e = msg.event.lw_session_logout.pointee
        eventData["username"] = String(cString: e.username.data)
        eventData["graphical_session_id"] = Int(e.graphical_session_id)
    case ES_EVENT_TYPE_NOTIFY_LW_SESSION_LOCK:
        let e = msg.event.lw_session_lock.pointee
        eventData["username"] = String(cString: e.username.data)
        eventData["graphical_session_id"] = Int(e.graphical_session_id)
    case ES_EVENT_TYPE_NOTIFY_LW_SESSION_UNLOCK:
        let e = msg.event.lw_session_unlock.pointee
        eventData["username"] = String(cString: e.username.data)
        eventData["graphical_session_id"] = Int(e.graphical_session_id)
    case ES_EVENT_TYPE_NOTIFY_SCREENSHARING_ATTACH:
        let e = msg.event.screensharing_attach.pointee
        eventData["success"] = Bool(e.success)
        eventData["source_address_type"] = Int(e.source_address_type.rawValue)
        eventData["source_address"] = String(cString: e.source_address.data)
        eventData["viewer_appleid"] = String(cString: e.viewer_appleid.data)
        eventData["authentication_type"] = String(cString: e.authentication_type.data)
        eventData["authentication_username"] = String(cString: e.authentication_username.data)
        eventData["session_username"] = String(cString: e.session_username.data)
        eventData["existing_session"] = Bool(e.existing_session)
        eventData["graphical_session_id"] = Int(e.graphical_session_id)
    case ES_EVENT_TYPE_NOTIFY_SCREENSHARING_DETACH:
        let e = msg.event.screensharing_detach.pointee
        eventData["source_address_type"] = Int(e.source_address_type.rawValue)
        eventData["source_address"] = String(cString: e.source_address.data)
        eventData["viewer_appleid"] = String(cString: e.viewer_appleid.data)
        eventData["graphical_session_id"] = Int(e.graphical_session_id)
    case ES_EVENT_TYPE_NOTIFY_OPENSSH_LOGIN:
        let e = msg.event.openssh_login.pointee
        eventData["success"] = Bool(e.success)
        eventData["result_type"] = Int(e.result_type.rawValue)
        eventData["source_address_type"] = Int(e.source_address_type.rawValue)
        eventData["source_address"] = String(cString: e.source_address.data)
        eventData["username"] = String(cString: e.username.data)
        eventData["has_uid"] = Bool(e.has_uid)
        if e.has_uid {
            eventData["uid"] = Int(e.uid.uid)
        }
    case ES_EVENT_TYPE_NOTIFY_OPENSSH_LOGOUT:
        let e = msg.event.openssh_logout.pointee
        eventData["source_address_type"] = Int(e.source_address_type.rawValue)
        eventData["source_address"] = String(cString: e.source_address.data)
        eventData["username"] = String(cString: e.username.data)
        eventData["uid"] = Int(e.uid)
    case ES_EVENT_TYPE_NOTIFY_SU:
        let e = msg.event.su.pointee
        eventData["success"] = Bool(e.success)
        eventData["failure_message"] = String(cString: e.failure_message.data)
        eventData["from_uid"] = Int(e.from_uid)
        eventData["from_username"] = String(cString: e.from_username.data)
        eventData["has_to_uid"] = Bool(e.has_to_uid)
        if e.has_to_uid {
            eventData["to_uid"] = Int(e.to_uid.uid)
        }
        eventData["to_username"] = String(cString: e.to_username.data)
        eventData["shell"] = String(cString: e.shell.data)
    case ES_EVENT_TYPE_NOTIFY_SUDO:
        let e = msg.event.sudo.pointee
        eventData["success"] = Bool(e.success)
        if let rejectInfo = e.reject_info {
            let ri = rejectInfo.pointee
            eventData["reject_plugin_name"] = String(cString: ri.plugin_name.data)
            eventData["reject_failure_message"] = String(cString: ri.failure_message.data)
        }
        if e.has_from_uid {
            eventData["from_uid"] = Int(e.from_uid.uid)
        }
        eventData["from_username"] = String(cString: e.from_username.data)
        eventData["has_to_uid"] = Bool(e.has_to_uid)
        if e.has_to_uid {
            eventData["to_uid"] = Int(e.to_uid.uid)
        }
        eventData["to_username"] = String(cString: e.to_username.data)
        eventData["command"] = String(cString: e.command.data)

    case ES_EVENT_TYPE_NOTIFY_AUTHENTICATION:
        let e = msg.event.authentication.pointee
        eventData["success"] = Bool(e.success)
        eventData["type"] = Int(e.type.rawValue)

    case ES_EVENT_TYPE_NOTIFY_AUTHORIZATION_PETITION:
        let e = msg.event.authorization_petition.pointee
        if let instigator = e.instigator {
            eventData["instigator"] = extractProcessInfo(instigator)
        }
        eventData["flags"] = Int(e.flags)
    case ES_EVENT_TYPE_NOTIFY_AUTHORIZATION_JUDGEMENT:
        let e = msg.event.authorization_judgement.pointee
        if let instigator = e.instigator {
            eventData["instigator"] = extractProcessInfo(instigator)
        }
        eventData["return_code"] = Int(e.return_code)

    case ES_EVENT_TYPE_NOTIFY_BTM_LAUNCH_ITEM_ADD:
        let btm = msg.event.btm_launch_item_add.pointee
        if let instigator = btm.instigator { eventData["instigator"] = extractProcessInfo(instigator) }
        if let app = btm.app { eventData["app"] = extractProcessInfo(app) }
        let item = btm.item.pointee
        eventData["item_type"] = Int(item.item_type.rawValue)
        eventData["item_url"] = String(cString: item.item_url.data)
        eventData["is_legacy"] = Bool(item.legacy)
        eventData["is_managed"] = Bool(item.managed)
        eventData["uid"] = Int(item.uid)
    case ES_EVENT_TYPE_NOTIFY_BTM_LAUNCH_ITEM_REMOVE:
        let btm = msg.event.btm_launch_item_remove.pointee
        if let instigator = btm.instigator { eventData["instigator"] = extractProcessInfo(instigator) }
        if let app = btm.app { eventData["app"] = extractProcessInfo(app) }
        let item = btm.item.pointee
        eventData["item_type"] = Int(item.item_type.rawValue)
        eventData["item_url"] = String(cString: item.item_url.data)
        eventData["is_legacy"] = Bool(item.legacy)
        eventData["is_managed"] = Bool(item.managed)
        eventData["uid"] = Int(item.uid)

    case ES_EVENT_TYPE_NOTIFY_PROFILE_ADD:
        let e = msg.event.profile_add.pointee
        if let instigator = e.instigator { eventData["instigator"] = extractProcessInfo(instigator) }
        eventData["is_update"] = Bool(e.is_update)
        let profile = e.profile.pointee
        eventData["profile_identifier"] = String(cString: profile.identifier.data)
        eventData["profile_uuid"] = String(cString: profile.uuid.data)
        eventData["profile_organization"] = String(cString: profile.organization.data)
        eventData["profile_display_name"] = String(cString: profile.display_name.data)
        eventData["profile_scope"] = String(cString: profile.scope.data)
    case ES_EVENT_TYPE_NOTIFY_PROFILE_REMOVE:
        let e = msg.event.profile_remove.pointee
        if let instigator = e.instigator { eventData["instigator"] = extractProcessInfo(instigator) }
        let profile = e.profile.pointee
        eventData["profile_identifier"] = String(cString: profile.identifier.data)
        eventData["profile_uuid"] = String(cString: profile.uuid.data)
        eventData["profile_organization"] = String(cString: profile.organization.data)
        eventData["profile_display_name"] = String(cString: profile.display_name.data)
        eventData["profile_scope"] = String(cString: profile.scope.data)

    case ES_EVENT_TYPE_NOTIFY_XP_MALWARE_DETECTED:
        let e = msg.event.xp_malware_detected.pointee
        eventData["malware_identifier"] = String(cString: e.malware_identifier.data)
        eventData["signature_version"] = String(cString: e.signature_version.data)
        eventData["incident_identifier"] = String(cString: e.incident_identifier.data)
        eventData["detected_path"] = String(cString: e.detected_path.data)
    case ES_EVENT_TYPE_NOTIFY_XP_MALWARE_REMEDIATED:
        let e = msg.event.xp_malware_remediated.pointee
        eventData["malware_identifier"] = String(cString: e.malware_identifier.data)
        eventData["signature_version"] = String(cString: e.signature_version.data)
        eventData["incident_identifier"] = String(cString: e.incident_identifier.data)
        eventData["action_type"] = String(cString: e.action_type.data)
        eventData["success"] = Bool(e.success)
        eventData["remediated_path"] = String(cString: e.remediated_path.data)
        if let token = e.remediated_process_audit_token {
            eventData["remediated_process_pid"] = Int(audit_token_to_pid(token.pointee))
        }

    case ES_EVENT_TYPE_NOTIFY_OD_CREATE_USER:
        let e = msg.event.od_create_user.pointee
        if let instigator = e.instigator { eventData["instigator"] = extractProcessInfo(instigator) }
        eventData["user_name"] = String(cString: e.user_name.data)
        eventData["node_name"] = String(cString: e.node_name.data)
        eventData["db_path"] = String(cString: e.db_path.data)
        eventData["error_code"] = Int(e.error_code)
    case ES_EVENT_TYPE_NOTIFY_OD_DELETE_USER:
        let e = msg.event.od_delete_user.pointee
        if let instigator = e.instigator { eventData["instigator"] = extractProcessInfo(instigator) }
        eventData["user_name"] = String(cString: e.user_name.data)
        eventData["node_name"] = String(cString: e.node_name.data)
        eventData["db_path"] = String(cString: e.db_path.data)
        eventData["error_code"] = Int(e.error_code)
    case ES_EVENT_TYPE_NOTIFY_OD_ENABLE_USER:
        let e = msg.event.od_enable_user.pointee
        if let instigator = e.instigator { eventData["instigator"] = extractProcessInfo(instigator) }
        eventData["user_name"] = String(cString: e.user_name.data)
        eventData["node_name"] = String(cString: e.node_name.data)
        eventData["db_path"] = String(cString: e.db_path.data)
        eventData["error_code"] = Int(e.error_code)
    case ES_EVENT_TYPE_NOTIFY_OD_DISABLE_USER:
        let e = msg.event.od_disable_user.pointee
        if let instigator = e.instigator { eventData["instigator"] = extractProcessInfo(instigator) }
        eventData["user_name"] = String(cString: e.user_name.data)
        eventData["node_name"] = String(cString: e.node_name.data)
        eventData["db_path"] = String(cString: e.db_path.data)
        eventData["error_code"] = Int(e.error_code)
    case ES_EVENT_TYPE_NOTIFY_OD_MODIFY_PASSWORD:
        let e = msg.event.od_modify_password.pointee
        if let instigator = e.instigator { eventData["instigator"] = extractProcessInfo(instigator) }
        eventData["account_name"] = String(cString: e.account_name.data)
        eventData["account_type"] = Int(e.account_type.rawValue)
        eventData["node_name"] = String(cString: e.node_name.data)
        eventData["db_path"] = String(cString: e.db_path.data)
        eventData["error_code"] = Int(e.error_code)
    case ES_EVENT_TYPE_NOTIFY_OD_CREATE_GROUP:
        let e = msg.event.od_create_group.pointee
        if let instigator = e.instigator { eventData["instigator"] = extractProcessInfo(instigator) }
        eventData["group_name"] = String(cString: e.group_name.data)
        eventData["node_name"] = String(cString: e.node_name.data)
        eventData["db_path"] = String(cString: e.db_path.data)
        eventData["error_code"] = Int(e.error_code)
    case ES_EVENT_TYPE_NOTIFY_OD_DELETE_GROUP:
        let e = msg.event.od_delete_group.pointee
        if let instigator = e.instigator { eventData["instigator"] = extractProcessInfo(instigator) }
        eventData["group_name"] = String(cString: e.group_name.data)
        eventData["node_name"] = String(cString: e.node_name.data)
        eventData["db_path"] = String(cString: e.db_path.data)
        eventData["error_code"] = Int(e.error_code)
    case ES_EVENT_TYPE_NOTIFY_OD_GROUP_ADD:
        let e = msg.event.od_group_add.pointee
        if let instigator = e.instigator { eventData["instigator"] = extractProcessInfo(instigator) }
        eventData["group_name"] = String(cString: e.group_name.data)
        eventData["node_name"] = String(cString: e.node_name.data)
        eventData["db_path"] = String(cString: e.db_path.data)
        eventData["error_code"] = Int(e.error_code)
    case ES_EVENT_TYPE_NOTIFY_OD_GROUP_REMOVE:
        let e = msg.event.od_group_remove.pointee
        if let instigator = e.instigator { eventData["instigator"] = extractProcessInfo(instigator) }
        eventData["group_name"] = String(cString: e.group_name.data)
        eventData["node_name"] = String(cString: e.node_name.data)
        eventData["db_path"] = String(cString: e.db_path.data)
        eventData["error_code"] = Int(e.error_code)
    case ES_EVENT_TYPE_NOTIFY_OD_GROUP_SET:
        let e = msg.event.od_group_set.pointee
        if let instigator = e.instigator { eventData["instigator"] = extractProcessInfo(instigator) }
        eventData["group_name"] = String(cString: e.group_name.data)
        eventData["node_name"] = String(cString: e.node_name.data)
        eventData["db_path"] = String(cString: e.db_path.data)
        eventData["error_code"] = Int(e.error_code)
    case ES_EVENT_TYPE_NOTIFY_OD_ATTRIBUTE_SET:
        let e = msg.event.od_attribute_set.pointee
        if let instigator = e.instigator { eventData["instigator"] = extractProcessInfo(instigator) }
        eventData["record_type"] = Int(e.record_type.rawValue)
        eventData["record_name"] = String(cString: e.record_name.data)
        eventData["attribute_name"] = String(cString: e.attribute_name.data)
        eventData["node_name"] = String(cString: e.node_name.data)
        eventData["db_path"] = String(cString: e.db_path.data)
        eventData["error_code"] = Int(e.error_code)
    case ES_EVENT_TYPE_NOTIFY_OD_ATTRIBUTE_VALUE_ADD:
        let e = msg.event.od_attribute_value_add.pointee
        if let instigator = e.instigator { eventData["instigator"] = extractProcessInfo(instigator) }
        eventData["record_type"] = Int(e.record_type.rawValue)
        eventData["record_name"] = String(cString: e.record_name.data)
        eventData["attribute_name"] = String(cString: e.attribute_name.data)
        eventData["attribute_value"] = String(cString: e.attribute_value.data)
        eventData["node_name"] = String(cString: e.node_name.data)
        eventData["db_path"] = String(cString: e.db_path.data)
        eventData["error_code"] = Int(e.error_code)
    case ES_EVENT_TYPE_NOTIFY_OD_ATTRIBUTE_VALUE_REMOVE:
        let e = msg.event.od_attribute_value_remove.pointee
        if let instigator = e.instigator { eventData["instigator"] = extractProcessInfo(instigator) }
        eventData["record_type"] = Int(e.record_type.rawValue)
        eventData["record_name"] = String(cString: e.record_name.data)
        eventData["attribute_name"] = String(cString: e.attribute_name.data)
        eventData["attribute_value"] = String(cString: e.attribute_value.data)
        eventData["node_name"] = String(cString: e.node_name.data)
        eventData["db_path"] = String(cString: e.db_path.data)
        eventData["error_code"] = Int(e.error_code)

    default:
        break
    }

    if !eventData.isEmpty {
        result["event"] = eventData
    }

    return result
}

class EventCollector {
    private var client: OpaquePointer?
    private let eventSet: Int
    private let logPath: String
    private let stopFlag: Atomic<Bool>
    private let sampleHash: String
    private var startLogging: Bool

    private var pendingWrites: [String: String] = [:]
    private let writeQueue: DispatchQueue
    private static let flushThreshold = 50

    private let ignoredSigningIds: Set<String> = [
        "com.apple.BiomeAgent",
        "com.apple.proactived",
        "com.apple.xpc.launchd",
        "com.developerid.silimon", // placeholder
        "com.apple.mds_stores",
        "com.apple.ContextStoreAgent",
        "com.apple.UserEventAgent",
        "com.apple.STMExtension.Applications",
        "com.apple.mdworker_shared"
    ]

    private let ignoredPaths: Set<String> = [
        "/System/Library/PrivateFrameworks/StorageManagement.framework/PlugIns/StorageManagementService",
        "/usr/libexec/logd",
        "/usr/sbin/cfprefsd",
        "/System/Library/Frameworks/AppKit.framework/Versions/C/XPCServices/com.apple.appkit.xpc.openAndSavePanelService.xpc/Contents/MacOS/com.apple.appkit.xpc.openAndSavePanelService"
    ]

    init(stopFlag: Atomic<Bool>, eventSet: Int, sampleHash: String = "") {
        self.stopFlag = stopFlag
        self.eventSet = eventSet
        self.sampleHash = sampleHash
        self.startLogging = sampleHash.isEmpty
        self.writeQueue = DispatchQueue(label: "silimon.write.\(eventSet)")

        let eventTypeNames: Set<String>
        switch eventSet {
        case 0:
            eventTypeNames = ecEventTypesMain
            self.logPath = logPaths["main_esf"]!
        case 1:
            eventTypeNames = ecEventTypesExtra
            self.logPath = logPaths["extra_esf"]!
        case 2:
            eventTypeNames = ecEventTypesRare
            self.logPath = logPaths["rare_esf"]!
        default:
            eventTypeNames = ecEventTypesMain
            self.logPath = logPaths["main_esf"]!
        }

        var events = resolveEventTypes(from: eventTypeNames)
        guard !events.isEmpty else {
            print("No valid event types resolved for event set \(eventSet)")
            return
        }

        let result = es_new_client(&client) { [weak self] _, message in
            self?.handleEvent(message)
        }

        guard result == ES_NEW_CLIENT_RESULT_SUCCESS else {
            print("Failed to create ES client: \(esClientErrorDescription(result))")
            return
        }

        let subscribeResult = es_subscribe(client!, &events, UInt32(events.count))
        guard subscribeResult == ES_RETURN_SUCCESS else {
            print("Failed to subscribe to events for set \(eventSet)")
            return
        }
    }

    private func handleEvent(_ message: UnsafePointer<es_message_t>) {
        if shouldFilterEvent(message) { return }

        if !startLogging {
            let process = message.pointee.process.pointee
            let cdhashHex = withUnsafeBytes(of: process.cdhash) { bytes in
                bytes.prefix(20).map { String(format: "%02x", $0) }.joined()
            }
            if cdhashHex == sampleHash {
                startLogging = true
            }
        }

        guard startLogging, !stopFlag.value else { return }

        guard let eventDict = serializeMessage(message) else { return }

        guard let jsonData = try? JSONSerialization.data(withJSONObject: eventDict, options: []),
              let jsonString = String(data: jsonData, encoding: .utf8) else {
            return
        }

        let startTime = formatTimeval(message.pointee.process.pointee.start_time)
        let seqNum = String(message.pointee.global_seq_num)
        let key = "\(startTime)_\(seqNum)"

        writeQueue.async { [weak self] in
            guard let self = self else { return }
            self.pendingWrites[key] = jsonString
            if self.pendingWrites.count >= EventCollector.flushThreshold {
                self.flush()
            }
        }
    }

    private func flush() {
        guard !pendingWrites.isEmpty else { return }
        appendToJSONFile(toolOutputs: pendingWrites, logPath: logPath)
        pendingWrites.removeAll()
    }

    private func shouldFilterEvent(_ message: UnsafePointer<es_message_t>) -> Bool {
        let process = message.pointee.process.pointee
        let processPath = String(cString: process.executable.pointee.path.data)
        let signingId = String(cString: process.signing_id.data)
        let eventType = message.pointee.event_type

        if ignoredSigningIds.contains(signingId) { return true }
        if ignoredPaths.contains(processPath) { return true }

        if eventType == ES_EVENT_TYPE_NOTIFY_WRITE {
            if signingId == "com.apple.syslogd" && processPath.contains("/private/var/log") {
                return true
            }
        }

        if signingId == "com.apple.fseventsd" {
            if eventType == ES_EVENT_TYPE_NOTIFY_LOOKUP ||
               eventType == ES_EVENT_TYPE_NOTIFY_STAT ||
               eventType == ES_EVENT_TYPE_NOTIFY_ACCESS {
                return true
            }
        }

        if eventType == ES_EVENT_TYPE_NOTIFY_PROC_CHECK &&
           processPath.contains("/usr/sbin/distnoted") {
            return true
        }

        return false
    }

    private func esClientErrorDescription(_ result: es_new_client_result_t) -> String {
        switch result {
        case ES_NEW_CLIENT_RESULT_SUCCESS: return "Success"
        case ES_NEW_CLIENT_RESULT_ERR_INVALID_ARGUMENT: return "Invalid argument"
        case ES_NEW_CLIENT_RESULT_ERR_INTERNAL: return "Internal error"
        case ES_NEW_CLIENT_RESULT_ERR_NOT_ENTITLED: return "Not entitled"
        case ES_NEW_CLIENT_RESULT_ERR_NOT_PERMITTED: return "Not permitted"
        case ES_NEW_CLIENT_RESULT_ERR_NOT_PRIVILEGED: return "Not privileged"
        default: return "Unknown error"
        }
    }

    func stop() {
        if let client = client {
            es_unsubscribe_all(client)
            es_delete_client(client)
            self.client = nil
        }
        writeQueue.sync { flush() }
    }

    deinit {
        stop()
    }
}

func startRawEventMonitoring(stopFlag: Atomic<Bool>, eventSet: Int, dispatchGroup: DispatchGroup, sampleHash: String = "") {
    dispatchGroup.enter()
    DispatchQueue.global().async {
        defer { dispatchGroup.leave() }

        let collector = EventCollector(stopFlag: stopFlag, eventSet: eventSet, sampleHash: sampleHash)

        while !stopFlag.value {
            Thread.sleep(forTimeInterval: 1)
        }

        collector.stop()
    }
}
