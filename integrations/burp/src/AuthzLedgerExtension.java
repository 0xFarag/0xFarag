// © Nasser Aldin Farag (0xFarag). All rights reserved.
package ch.zeroxfarag.authzledger.burp;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.ui.contextmenu.ContextMenuEvent;
import burp.api.montoya.ui.contextmenu.ContextMenuItemsProvider;
import burp.api.montoya.ui.contextmenu.InvocationType;

import javax.swing.JFileChooser;
import javax.swing.JMenuItem;
import javax.swing.JOptionPane;
import javax.swing.SwingWorker;
import java.awt.Component;
import java.io.File;
import java.nio.file.FileAlreadyExistsException;
import java.nio.file.Path;
import java.util.List;
import java.util.concurrent.ExecutionException;

public final class AuthzLedgerExtension implements BurpExtension, ContextMenuItemsProvider {
    @Override
    public void initialize(MontoyaApi api) {
        api.extension().setName("AuthzLedger Evidence Export");
        api.userInterface().registerContextMenuItemsProvider(this);
    }

    @Override
    public List<Component> provideMenuItems(ContextMenuEvent event) {
        if (event.invocationType() != InvocationType.PROXY_HISTORY) return List.of();
        List<HttpRequestResponse> rows = event.selectedRequestResponses();
        if (rows.isEmpty()) return List.of();

        JMenuItem item = new JMenuItem("Export selected evidence to AuthzLedger…");
        if (rows.size() > EvidenceXml.MAX_ROWS) {
            item.setEnabled(false);
            item.setToolTipText("Select up to " + EvidenceXml.MAX_ROWS + " recorded exchanges.");
        } else {
            List<HttpRequestResponse> selection = List.copyOf(rows);
            item.addActionListener(ignored -> chooseDestination(selection));
        }
        return List.of(item);
    }

    private void chooseDestination(List<HttpRequestResponse> selection) {
        JFileChooser chooser = new JFileChooser();
        chooser.setDialogTitle("Save original HTTP messages to a restricted evidence folder");
        chooser.setSelectedFile(new File("authzledger-burp.xml"));
        if (chooser.showSaveDialog(null) != JFileChooser.APPROVE_OPTION) return;
        Path destination = chooser.getSelectedFile().toPath().toAbsolutePath();
        int answer = JOptionPane.showConfirmDialog(null,
                "Write " + selection.size() + " complete exchange(s) to the selected file?\n"
                + "Original headers, cookies, tokens and bodies can contain sensitive data.\n"
                + "Use a folder approved for this engagement.",
                "Confirm evidence export", JOptionPane.OK_CANCEL_OPTION, JOptionPane.WARNING_MESSAGE);
        if (answer != JOptionPane.OK_OPTION) return;
        new SwingWorker<Void, Void>() {
            @Override
            protected Void doInBackground() throws Exception {
                EvidenceXml.saveNew(destination, EvidenceXml.encode(selection));
                return null;
            }
            @Override
            protected void done() {
                try {
                    get();
                    JOptionPane.showMessageDialog(null, selection.size() + " exchange(s) saved.",
                            "AuthzLedger", JOptionPane.INFORMATION_MESSAGE);
                } catch (InterruptedException interrupted) {
                    Thread.currentThread().interrupt();
                    showError("Export interrupted. Check the selected location.");
                } catch (ExecutionException failure) {
                    Throwable cause = failure.getCause();
                    if (cause instanceof EvidenceXml.InvalidSelection) showError(cause.getMessage());
                    else if (cause instanceof FileAlreadyExistsException) showError("Choose a new file name.");
                    else showError("Could not finish the export. Check folder access and whether the file system supports hard links.");
                }
            }
        }.execute();
    }

    private static void showError(String message) {
        JOptionPane.showMessageDialog(null, message, "AuthzLedger", JOptionPane.ERROR_MESSAGE);
    }
}
