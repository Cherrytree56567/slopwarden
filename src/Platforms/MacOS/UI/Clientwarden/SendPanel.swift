import SwiftUI
import UniformTypeIdentifiers

/*
 * Bitwarden Send: the user's Sends (text or file shared by link) and opening Sends that
 * others shared. SendPanel is the data, the views below display it, like the other panels.
 */

@objc
enum SendKind: Int {
    case Text
    case File
}

/*
 * Everything the UI shows and edits about one Send. Dates of 0 mean "not set".
 */
@objcMembers
final class SendDetail: NSObject {
    public var id: String = ""
    public var kind: SendKind = .Text
    public var name: String = ""
    public var notes: String = ""
    public var text: String = ""
    public var textHidden: Bool = false
    public var fileName: String = ""
    public var fileSize: String = ""
    public var maxAccessCount: Int = 0      // 0 = unlimited
    public var accessCount: Int = 0
    public var expirationDate: Double = 0   // seconds since 1970
    public var deletionDate: Double = 0
    public var disabled: Bool = false
    public var hideEmail: Bool = false
    public var hasPassword: Bool = false
    public var shareUrl: String = ""
}

/*
 * The result of opening someone's Send link. status: 0 ok, 1 needs password,
 * 2 wrong password, 3 not available, 4 invalid link, 5 offline, 6 failed.
 */
@objcMembers
final class ReceivedSendData: NSObject {
    public var status: Int = 6
    public var kind: SendKind = .Text
    public var name: String = ""
    public var text: String = ""
    public var textHidden: Bool = false
    public var fileName: String = ""
    public var fileSize: String = ""
    public var creator: String = ""
}

@objcMembers
@Observable
final class SendPanel: NSObject {
    static let instance = SendPanel()

    public var sends: [SendDetail] = []
    public var selectedId: String? = nil
    public var editing: SendDetail? = nil
    public var newPassword: String = ""
    public var pendingFile: URL? = nil

    @objc public var cb_getSends: (() -> [SendDetail])?
    @objc public var cb_newSend: ((SendKind) -> SendDetail?)?
    /*
     * cb_saveSend(detail, newPassword, filePath) -> saved Send, or nil on failure
     */
    @objc public var cb_saveSend: ((SendDetail, String, String) -> SendDetail?)?
    @objc public var cb_deleteSend: ((String) -> Bool)?
    @objc public var cb_removeSendPassword: ((String) -> Bool)?
    @objc public var cb_openSend: ((String, String) -> ReceivedSendData)?
    @objc public var cb_downloadReceivedFile: ((String) -> Bool)?

    func reload() {
        if let result = cb_getSends?() {
            sends = result
            if let id = selectedId, editing?.id == id, let fresh = sends.first(where: { $0.id == id }) {
                editing = fresh
            }
        } else {
            ToastStore.instance.toasts.append(Toast(message: "No callback set for getSends"))
        }
    }

    func select(_ send: SendDetail) {
        selectedId = send.id
        editing = send
        newPassword = ""
        pendingFile = nil
    }

    func create(kind: SendKind) {
        if let send = cb_newSend?(kind) {
            selectedId = nil
            editing = send
            newPassword = ""
            pendingFile = nil
        } else {
            ToastStore.instance.toasts.append(Toast(message: "Couldn't start a new Send"))
        }
    }

    func save() {
        guard let send = editing else { return }
        if let saved = cb_saveSend?(send, newPassword, pendingFile?.path ?? "") {
            newPassword = ""
            pendingFile = nil
            selectedId = saved.id
            editing = saved
            reload()
        } else {
            ToastStore.instance.toasts.append(Toast(message: "Failed to save Send"))
        }
    }

    func delete() {
        guard let send = editing else { return }
        if send.id.isEmpty || (cb_deleteSend?(send.id) ?? false) {
            editing = nil
            selectedId = nil
            reload()
        } else {
            ToastStore.instance.toasts.append(Toast(message: "Failed to delete Send"))
        }
    }

    func removePassword() {
        guard let send = editing, !send.id.isEmpty else { return }
        if (cb_removeSendPassword?(send.id) ?? false) {
            reload()
        } else {
            ToastStore.instance.toasts.append(Toast(message: "Failed to remove the password"))
        }
    }

    func copyLink() {
        guard let link = editing?.shareUrl, !link.isEmpty else { return }
        /*
         * The link carries the Send's key, so it goes through the clipboard that clears itself.
         */
        Clipboard.instance.copy(link)
        ToastStore.instance.toasts.append(Toast(message: "Link copied"))
    }
}

struct SendListView: View {
    @Bindable var data: SendPanel = SendPanel.instance
    @State private var showOpenSheet: Bool = false

    var body: some View {
        List(selection: Binding(get: { data.selectedId }, set: { id in
            if let id, let send = data.sends.first(where: { $0.id == id }) {
                data.select(send)
            }
        })) {
            ForEach(data.sends, id: \.id) { send in
                HStack {
                    Image(systemName: send.kind == .File ? "doc" : "text.alignleft")
                    VStack(alignment: .leading) {
                        Text(send.name.isEmpty ? "Untitled" : send.name)
                        Text(statusLine(send))
                            .font(.caption)
                            .foregroundStyle(.secondary)
                    }
                    Spacer()
                    if (send.hasPassword) {
                        Image(systemName: "key")
                            .foregroundStyle(.secondary)
                    }
                    if (send.disabled) {
                        Image(systemName: "nosign")
                            .foregroundStyle(.secondary)
                    }
                }
                .tag(send.id)
            }
        }
        .overlay {
            if (data.sends.isEmpty) {
                ContentUnavailableView("No Sends", systemImage: "paperplane",
                                       description: Text("Share text or a file securely with a link"))
            }
        }
        .toolbar {
            ToolbarItem {
                Menu {
                    Button("Text Send") { data.create(kind: .Text) }
                    Button("File Send") { data.create(kind: .File) }
                } label: {
                    Image(systemName: "plus")
                }
            }
            ToolbarItem {
                Button {
                    showOpenSheet = true
                } label: {
                    Image(systemName: "link")
                }
                .help("Open a Send link…")
            }
        }
        .sheet(isPresented: $showOpenSheet) {
            ReceiveSendSheet(isPresented: $showOpenSheet)
        }
        .onAppear {
            #if NON_XCODE_BUILD
                SendBridge.setupCallbacks()
            #endif
            data.reload()
        }
        .frame(minWidth: 220)
    }

    private func statusLine(_ send: SendDetail) -> String {
        let deletion = Date(timeIntervalSince1970: send.deletionDate)
        let views = send.maxAccessCount > 0 ? "\(send.accessCount)/\(send.maxAccessCount) views" : "\(send.accessCount) views"
        return "\(views) · deleted \(deletion.formatted(.relative(presentation: .named)))"
    }
}

struct SendDetailView: View {
    @Bindable var data: SendPanel = SendPanel.instance
    @State private var showFilePicker: Bool = false
    @State private var showDeleteConfirm: Bool = false

    var body: some View {
        if let send = data.editing {
            Form {
                Section {
                    TextField("Name", text: Binding(get: { send.name }, set: { send.name = $0 }))
                    if (send.kind == .Text) {
                        TextField("Text", text: Binding(get: { send.text }, set: { send.text = $0 }), axis: .vertical)
                            .lineLimit(3...8)
                        Toggle("Hide the text by default", isOn: Binding(get: { send.textHidden }, set: { send.textHidden = $0 }))
                    } else if (send.id.isEmpty) {
                        HStack {
                            Text(data.pendingFile?.lastPathComponent ?? "No file chosen")
                                .foregroundStyle(.secondary)
                            Spacer()
                            Button("Choose File…") { showFilePicker = true }
                        }
                    } else {
                        LabeledContent("File", value: "\(send.fileName) (\(send.fileSize))")
                    }
                }

                Section("Options") {
                    DatePicker("Deletion date",
                               selection: Binding(get: { Date(timeIntervalSince1970: send.deletionDate) },
                                                  set: { send.deletionDate = $0.timeIntervalSince1970 }),
                               in: Date()...Date().addingTimeInterval(31 * 86400))
                    Toggle("Expires", isOn: Binding(get: { send.expirationDate > 0 },
                                                    set: { send.expirationDate = $0 ? Date().addingTimeInterval(86400).timeIntervalSince1970 : 0 }))
                    if (send.expirationDate > 0) {
                        DatePicker("Expiration date",
                                   selection: Binding(get: { Date(timeIntervalSince1970: send.expirationDate) },
                                                      set: { send.expirationDate = $0.timeIntervalSince1970 }),
                                   in: Date()...)
                    }
                    Stepper(send.maxAccessCount == 0 ? "Unlimited views" : "At most \(send.maxAccessCount) views",
                            value: Binding(get: { send.maxAccessCount }, set: { send.maxAccessCount = max(0, $0) }),
                            in: 0...1000)
                    SecureField(send.hasPassword ? "New password (leave empty to keep)" : "Password (optional)",
                                text: $data.newPassword)
                    if (send.hasPassword && !send.id.isEmpty) {
                        Button("Remove Password") { data.removePassword() }
                    }
                    Toggle("Hide my email from recipients", isOn: Binding(get: { send.hideEmail }, set: { send.hideEmail = $0 }))
                    Toggle("Disable this Send", isOn: Binding(get: { send.disabled }, set: { send.disabled = $0 }))
                    TextField("Private notes", text: Binding(get: { send.notes }, set: { send.notes = $0 }), axis: .vertical)
                }

                if (!send.shareUrl.isEmpty) {
                    Section("Link") {
                        HStack {
                            Text(send.shareUrl)
                                .lineLimit(1)
                                .truncationMode(.middle)
                                .foregroundStyle(.secondary)
                            Spacer()
                            Button("Copy") { data.copyLink() }
                        }
                    }
                }
            }
            .formStyle(.grouped)
            .toolbar {
                ToolbarItem {
                    Button("Save") { data.save() }
                        .keyboardShortcut("s")
                }
                ToolbarItem {
                    Button(role: .destructive) {
                        showDeleteConfirm = true
                    } label: {
                        Image(systemName: "trash")
                    }
                }
            }
            .fileImporter(isPresented: $showFilePicker, allowedContentTypes: [.item]) { result in
                if case .success(let url) = result {
                    data.pendingFile = url
                    if (send.name.isEmpty) {
                        send.name = url.lastPathComponent
                    }
                }
            }
            .alert("Delete Send", isPresented: $showDeleteConfirm) {
                Button("Cancel", role: .cancel) { }
                Button("Delete", role: .destructive) { data.delete() }
            } message: {
                Text("The link will stop working.")
            }
        } else {
            ContentUnavailableView("Send", systemImage: "paperplane",
                                   description: Text("Select a Send, or create one with +"))
        }
    }
}

/*
 * Opens a Send link someone shared: asks for its password if it has one, shows the text,
 * or saves the file.
 */
struct ReceiveSendSheet: View {
    @Binding var isPresented: Bool
    @State private var link: String = ""
    @State private var password: String = ""
    @State private var needsPassword: Bool = false
    @State private var received: ReceivedSendData? = nil
    @State private var revealed: Bool = false
    @State private var message: String = ""

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("Open a Send").font(.headline)

            if let received, received.status == 0 {
                Text(received.name).font(.title3.bold())
                if (!received.creator.isEmpty) {
                    Text("Shared by \(received.creator)").font(.caption).foregroundStyle(.secondary)
                }
                if (received.kind == .Text) {
                    if (received.textHidden && !revealed) {
                        Button("Reveal text") { revealed = true }
                    } else {
                        ScrollView {
                            Text(received.text).textSelection(.enabled).frame(maxWidth: .infinity, alignment: .leading)
                        }
                        .frame(maxHeight: 160)
                        Button("Copy") { Clipboard.instance.copy(received.text) }
                    }
                } else {
                    LabeledContent("File", value: "\(received.fileName) (\(received.fileSize))")
                    Button("Save File…") { saveFile(received) }
                }
            } else {
                TextField("https://…/#/send/…", text: $link)
                if (needsPassword) {
                    SecureField("Password", text: $password)
                }
                if (!message.isEmpty) {
                    Text(message).font(.caption).foregroundStyle(.red)
                }
            }

            HStack {
                Spacer()
                Button("Close", role: .cancel) { isPresented = false }
                if (received?.status != 0) {
                    Button("Open") { open() }
                        .keyboardShortcut(.defaultAction)
                        .disabled(link.isEmpty)
                }
            }
        }
        .padding()
        .frame(width: 420)
    }

    private func open() {
        guard let result = SendPanel.instance.cb_openSend?(link, password) else {
            message = "No callback set for opening Sends"
            return
        }
        switch result.status {
            case 0: received = result; message = ""
            case 1: needsPassword = true; message = "This Send is password protected."
            case 2: needsPassword = true; message = "Wrong password."
            case 3: message = "This Send has expired, been deleted or reached its view limit."
            case 4: message = "That isn't a Send link."
            case 5: message = "Can't reach the server."
            default: message = "Couldn't open this Send."
        }
    }

    private func saveFile(_ received: ReceivedSendData) {
        let panel = NSSavePanel()
        panel.nameFieldStringValue = received.fileName
        if (panel.runModal() == .OK), let url = panel.url {
            if (!(SendPanel.instance.cb_downloadReceivedFile?(url.path) ?? false)) {
                ToastStore.instance.toasts.append(Toast(message: "Failed to download the file"))
            }
        }
    }
}
