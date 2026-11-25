// © Nasser Aldin Farag (0xFarag). All rights reserved.
package ch.zeroxfarag.authzledger.handoff;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.ui.contextmenu.*;
import javax.swing.*;
import javax.swing.table.DefaultTableModel;
import java.awt.BorderLayout;
import java.awt.Component;
import java.awt.Dimension;
import java.awt.GridLayout;
import java.net.URI;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.ExecutionException;

public final class AuthzLedgerHandoff implements BurpExtension, ContextMenuItemsProvider {
    private String previousDestination = "", previousHosts = ""; // Current extension session only.
    private static final String NOTICE = "© Nasser Aldin Farag (0xFarag). All rights reserved.";
    public void initialize(MontoyaApi api) {
        api.extension().setName("AuthzLedger Handoff");
        api.userInterface().registerContextMenuItemsProvider(this);
    }

    public List<Component> provideMenuItems(ContextMenuEvent event) {
        if (event.invocationType() != InvocationType.PROXY_HISTORY) return List.of();
        var selected = List.copyOf(event.selectedRequestResponses());
        if (selected.isEmpty()) return List.of();
        var menu = new JMenuItem("An AuthzLedger übergeben");
        menu.setEnabled(selected.size() <= ObservationBatch.MAX_ROWS);
        menu.addActionListener(unused -> prepare(selected));
        return List.of(menu);
    }

    private void prepare(List<HttpRequestResponse> selected) {
        var destination = new JTextField(previousDestination);
        var hosts = new JTextField(previousHosts);
        var token = new JPasswordField();
        var config = new JPanel(new GridLayout(0, 1, 0, 3));
        config.add(new JLabel("Workspace-URL mit /api/proof-import"));
        config.add(destination);
        config.add(new JLabel("Erlaubte Quellhosts (kommagetrennt)"));
        config.add(hosts);
        config.add(new JLabel("Kurzlebiges Import-Token des ausgewählten Prüflaufs"));
        config.add(token);
        config.add(new JLabel(NOTICE));
        int accepted = JOptionPane.showConfirmDialog(null, config, "AuthzLedger · Konfiguration",
                JOptionPane.OK_CANCEL_OPTION, JOptionPane.PLAIN_MESSAGE);
        char[] secret = token.getPassword();
        token.setText("");
        try {
            if (accepted != JOptionPane.OK_OPTION) return;
            URI target = Handoff.destination(destination.getText().strip());
            var allowlist = ObservationBatch.allowlist(hosts.getText());
            var rows = ObservationBatch.selected(selected, allowlist);
            previousDestination = target.toASCIIString();
            previousHosts = hosts.getText();
            Set<String> markers = preview(target, rows);
            if (markers != null) transmit(target, new String(secret), ObservationBatch.json(rows, markers), rows.size());
        } catch (IllegalArgumentException err) {
            error(err.getMessage());
        } finally {
            Arrays.fill(secret, '\0');
        }
    }

    private Set<String> preview(URI destination, List<ObservationBatch.Observation> rows) {
        var model = new DefaultTableModel(new Object[]{"Marker belegt", "Host", "Methode", "Pfad", "Status"},0) {
            public Class<?> getColumnClass(int col) { return col == 0 ? Boolean.class : String.class; }
            public boolean isCellEditable(int row, int col) { return col == 0; }
        };
        for (var row : rows) model.addRow(new Object[]{false,row.host(),row.method(),row.path(),Integer.toString(row.status())});
        var table = new JTable(model);
        table.getColumnModel().getColumn(3).setPreferredWidth(210);
        var panel = new JPanel(new BorderLayout(0,8));
        panel.add(new JLabel("Empfänger: " + destination.toASCIIString()), BorderLayout.NORTH);
        var scroll = new JScrollPane(table);
        scroll.setPreferredSize(new Dimension(770,Math.min(rows.size()*25+30, 360)));
        panel.add(scroll, BorderLayout.CENTER);
        panel.add(new JLabel("Marker einzeln bestätigen. OK übergibt genau diese Beobachtungen."), BorderLayout.SOUTH);
        if (JOptionPane.showConfirmDialog(null, panel, "AuthzLedger · Übergabe prüfen",
                JOptionPane.OK_CANCEL_OPTION, JOptionPane.PLAIN_MESSAGE) != JOptionPane.OK_OPTION) return null;
        if (table.isEditing()) table.getCellEditor().stopCellEditing();
        Set<String> result = new HashSet<>();
        for (int i = 0; i < rows.size(); i++) if (Boolean.TRUE.equals(model.getValueAt(i, 0))) result.add(rows.get(i).id());
        return result;
    }

    private void transmit(URI target, String token, String json, int count) {
        new SwingWorker<Void, Void>() {
            protected Void doInBackground() throws Exception { Handoff.send(target,token,json,count); return null; }
            protected void done() {
                try {
                    get();
                    JOptionPane.showMessageDialog(null, count + " Beobachtung(en) im Workspace übernommen.");
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    error("Übergabe unterbrochen. Prüflauf im Cockpit kontrollieren.");
                } catch (ExecutionException e) { error(e.getCause().getMessage()); }
            }
        }.execute();
    }
    private static void error(String text) { JOptionPane.showMessageDialog(null, text, "AuthzLedger", JOptionPane.ERROR_MESSAGE); }
}
