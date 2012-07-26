package org.megadevs.security.client.ui;

import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.Component;
import java.awt.Dimension;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.MouseEvent;
import java.math.BigInteger;
import java.sql.Date;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Vector;

import javax.swing.BorderFactory;
import javax.swing.JButton;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTable;
import javax.swing.ListSelectionModel;
import javax.swing.table.DefaultTableModel;
import javax.swing.table.TableCellRenderer;

import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.cert.X509CRLEntryHolder;

@SuppressWarnings("serial")
public class CertificatesPanel extends CustomJPanelAdapter {

	private UI mUI;

	private JTable activeDigitalSignatureCertificateTable;
	private DefaultTableModel activeDigitalSignatureCertificateTableModel;
	
	private JTable activeDataEnciphermentCertificateTable;
	private DefaultTableModel activeDataEnciphermentCertificateTableModel;
	
	private JTable oldCertificatesTable;
	private DefaultTableModel oldCertificatesTableModel;
	
	private ArrayList<Boolean> revoked;
	
	public CertificatesPanel(UI ui) {
		mUI = ui;
		
		setLayout(new BorderLayout());
		
		JPanel activeCertificates = new JPanel();
		activeCertificates.setLayout(new BorderLayout());
		
		activeDigitalSignatureCertificateTableModel = new DefaultTableModel();
		activeDigitalSignatureCertificateTable = new CustomJTableAdapter(activeDigitalSignatureCertificateTableModel);
		activeDigitalSignatureCertificateTable.setFillsViewportHeight(false);
		activeDigitalSignatureCertificateTable.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
		activeDigitalSignatureCertificateTable.addMouseListener(new CustomMouseAdapter() {
			@Override
			public void mouseClicked(MouseEvent e) {
				ListSelectionModel selectionModel = activeDataEnciphermentCertificateTable.getSelectionModel();
				selectionModel.clearSelection();
			}
		});
		activeDigitalSignatureCertificateTable.setColumnSelectionAllowed(false);
		
		activeDataEnciphermentCertificateTableModel = new DefaultTableModel();
		activeDataEnciphermentCertificateTable = new CustomJTableAdapter(activeDataEnciphermentCertificateTableModel);
		activeDataEnciphermentCertificateTable.setFillsViewportHeight(false);
		activeDataEnciphermentCertificateTable.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
		activeDataEnciphermentCertificateTable.addMouseListener(new CustomMouseAdapter() {
			@Override
			public void mouseClicked(MouseEvent e) {
				ListSelectionModel selectionModel = activeDigitalSignatureCertificateTable.getSelectionModel();
				selectionModel.clearSelection();
			}
		});
		activeDataEnciphermentCertificateTable.setColumnSelectionAllowed(false);
		
		JScrollPane digitalPane = new JScrollPane(activeDigitalSignatureCertificateTable, JScrollPane.VERTICAL_SCROLLBAR_NEVER, JScrollPane.HORIZONTAL_SCROLLBAR_NEVER);
		Dimension d = activeDigitalSignatureCertificateTable.getPreferredSize();
		digitalPane.setPreferredSize(new Dimension(d.width, activeDigitalSignatureCertificateTable.getRowHeight() * 4));
		digitalPane.setBorder(BorderFactory.createTitledBorder("Active Digital Signature Certificate"));
		JScrollPane enciphermentPane = new JScrollPane(activeDataEnciphermentCertificateTable, JScrollPane.VERTICAL_SCROLLBAR_NEVER, JScrollPane.HORIZONTAL_SCROLLBAR_NEVER);
		enciphermentPane.setPreferredSize(new Dimension(d.width, activeDataEnciphermentCertificateTable.getRowHeight() * 4));
		enciphermentPane.setBorder(BorderFactory.createTitledBorder("Active Data Encipherment Certificate"));
		
		JPanel activeCertificatesPanel = new JPanel();
		activeCertificatesPanel.setLayout(new BorderLayout());
		activeCertificatesPanel.add(digitalPane, BorderLayout.NORTH);
		activeCertificatesPanel.add(enciphermentPane, BorderLayout.SOUTH);
		
		JButton renewCertificate = new JButton("Renew certificate");
		renewCertificate.addActionListener(new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent event) {
				Integer ID = -1;
				
				if (!activeDigitalSignatureCertificateTable.getSelectionModel().isSelectionEmpty()) {
					int row = activeDigitalSignatureCertificateTable.getSelectedRow();
					ID = Integer.valueOf((String) activeDigitalSignatureCertificateTableModel.getValueAt(row, 0));
					mUI.getClient().renewCertificate(ID);
					mUI.setActiveDigitalSignatureCertificate(mUI.getClient().getActiveCertificate(new KeyUsage(KeyUsage.digitalSignature), false));
				} else {
					int row = activeDataEnciphermentCertificateTable.getSelectedRow();
					ID = Integer.valueOf((String) activeDataEnciphermentCertificateTableModel.getValueAt(row, 0));
					mUI.getClient().renewCertificate(ID);
					mUI.setActiveDataEnciphermentCertificate(mUI.getClient().getActiveCertificate(new KeyUsage(KeyUsage.dataEncipherment), false));
				}
				
				updateTablesData();
			}
		});
		
		JButton revokeCertificate = new JButton("Revoke certificate");
		revokeCertificate.addActionListener(new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent e) {
				Integer ID = -1;
				
				if (!activeDigitalSignatureCertificateTable.getSelectionModel().isSelectionEmpty()) {
					int row = activeDigitalSignatureCertificateTable.getSelectedRow();
					ID = Integer.valueOf((String) activeDigitalSignatureCertificateTableModel.getValueAt(row, 1));
					String result = mUI.getClient().revokeCertificate(ID);
					if (result.contains("OK")) {
						mUI.noValidDigitalSignatureCertificate();
						mUI.getClient().updateCRL();
						mUI.getCertificationRequestsPanel().updateTablesData();
						mUI.setActiveDigitalSignatureCertificate(null);
					}
					
				} else {
					int row = activeDataEnciphermentCertificateTable.getSelectedRow();
					ID = Integer.valueOf((String) activeDataEnciphermentCertificateTableModel.getValueAt(row, 1));
					String result = mUI.getClient().revokeCertificate(ID);
					if (result.contains("OK")) {
						mUI.getClient().updateCRL();
						mUI.setActiveDataEnciphermentCertificate(null);
					}
				}
				
				updateTablesData();
			}
		});
		
		JPanel buttonPanel = new JPanel();
		buttonPanel.add(renewCertificate);
		buttonPanel.add(revokeCertificate);
		
		activeCertificates.add(activeCertificatesPanel, BorderLayout.NORTH);
		activeCertificates.add(buttonPanel, BorderLayout.SOUTH);
		
		oldCertificatesTableModel = new DefaultTableModel();
		oldCertificatesTable = new CustomJTableAdapter(oldCertificatesTableModel) {
			@Override
			public Component prepareRenderer(TableCellRenderer renderer, int row, int column) {
				Component comp = super.prepareRenderer(renderer, row, column);
				
				if (revoked.get(row))
					comp.setBackground(Color.red);
				else comp.setBackground(Color.gray);
				
				return comp;
			}
			
			public boolean isCellEditable(int row, int column) {
				return false;
			}
		};
		oldCertificatesTable.setFillsViewportHeight(false);
		oldCertificatesTable.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
		oldCertificatesTable.setColumnSelectionAllowed(false);
		oldCertificatesTable.setRowSelectionAllowed(false);
		
		JScrollPane oldPane = new JScrollPane(oldCertificatesTable, JScrollPane.VERTICAL_SCROLLBAR_AS_NEEDED, JScrollPane.HORIZONTAL_SCROLLBAR_AS_NEEDED);
		oldPane.setBorder(BorderFactory.createTitledBorder("Old certificates"));
		
		updateTablesData();
		
		add(activeCertificates, BorderLayout.NORTH);
		add(oldPane, BorderLayout.CENTER);
	}
	
	@SuppressWarnings("unchecked")
	public void updateTablesData() {
		Vector<String> columnNames = new Vector<String>();
		columnNames.add("Serial");
		columnNames.add("Serial CA");
		columnNames.add("Not before");
		columnNames.add("Not after");
		columnNames.add("Subject");
		columnNames.add("Type");
		columnNames.add("Renewed");
		
		Vector<Vector<String>> digital = new Vector<Vector<String>>();
		Vector<String> digitalRow = new Vector<String>();
		ArrayList<Object[]> digitalDetails = mUI.getClient().getCertificatesDetailsList();
		for (Object[] data : digitalDetails) {
			Integer activeDigitalSignatureCertificate = mUI.getActiveDigitalSignatureCertificate();
			if (activeDigitalSignatureCertificate != null && ((Integer) data[0]).intValue() == activeDigitalSignatureCertificate.intValue()) {
				digitalRow.add(((Integer) data[0]).toString());
				digitalRow.add(((Integer) data[1]).toString());
				digitalRow.add(((Date) data[2]).toString());
				digitalRow.add(((Date) data[3]).toString());
				digitalRow.add((String) data[4]);
				digitalRow.add(((Integer) data[5]).toString());
				digitalRow.add(((Integer) data[6]).toString());
			}
		}
		digital.add(digitalRow);
		
		activeDigitalSignatureCertificateTableModel.setDataVector(digital, columnNames);
		activeDigitalSignatureCertificateTableModel.fireTableDataChanged();
		
		Vector<Vector<String>> encipherment = new Vector<Vector<String>>();
		Vector<String> enciphermentRow = new Vector<String>();
		ArrayList<Object[]> enciphermentDetails = mUI.getClient().getCertificatesDetailsList();
		for (Object[] data : enciphermentDetails) {
			Integer activeDataEnciphermentCertificate = mUI.getActiveDataEnciphermentCertificate();
			if (activeDataEnciphermentCertificate != null && ((Integer) data[0]).intValue() == activeDataEnciphermentCertificate.intValue()) {
				enciphermentRow.add(((Integer) data[0]).toString());
				enciphermentRow.add(((Integer) data[1]).toString());
				enciphermentRow.add(((Date) data[2]).toString());
				enciphermentRow.add(((Date) data[3]).toString());
				enciphermentRow.add((String) data[4]);
				enciphermentRow.add(((Integer) data[5]).toString());
				enciphermentRow.add(((Integer) data[6]).toString());
			}
		}
		encipherment.add(enciphermentRow);
		
		activeDataEnciphermentCertificateTableModel.setDataVector(encipherment, columnNames);
		activeDataEnciphermentCertificateTableModel.fireTableDataChanged();
		
		Vector<Vector<String>> old = new Vector<Vector<String>>();
		ArrayList<Object[]> details = mUI.getClient().getCertificatesDetailsList();
		Collection<X509CRLEntryHolder> crlEntries = mUI.getClient().getCRLFromDatabase().getRevokedCertificates();
		revoked = new ArrayList<Boolean>();
		
		for (Object[] cert : details) {
			Integer id = (Integer) cert[0];
			Integer activeDigitalSignatureCertificate = mUI.getActiveDigitalSignatureCertificate();
			Integer activeDataEnciphermentCertificate = mUI.getActiveDataEnciphermentCertificate();
			if ((activeDigitalSignatureCertificate != null && id.intValue() == activeDigitalSignatureCertificate.intValue()) || 
					(activeDataEnciphermentCertificate != null && id.intValue() == activeDataEnciphermentCertificate.intValue()))
						; //OBROBRIO
			else {
				Integer caID = (Integer) cert[1];
				boolean isRevoked = false;
				for (X509CRLEntryHolder crlEntry : crlEntries) {
					if (crlEntry.getSerialNumber().compareTo(new BigInteger(caID.toString())) == 0)
						isRevoked = true;
				}
				revoked.add(isRevoked);
				
				Vector<String> oldRow = new Vector<String>();
				oldRow.add(((Integer) cert[0]).toString());
				oldRow.add(((Integer) cert[1]).toString());
				oldRow.add(((Date) cert[2]).toString());
				oldRow.add(((Date) cert[3]).toString());
				oldRow.add((String) cert[4]);
				oldRow.add(((Integer) cert[5]).toString());
				oldRow.add(((Integer) cert[6]).toString());
				old.add(oldRow);
			}
		}
		
		oldCertificatesTableModel.setDataVector(old, columnNames);
		oldCertificatesTableModel.fireTableDataChanged();
	}

	@Override
	public void updateData() {
		updateTablesData();
	}

}
