package org.megadevs.security.client.ui;

import java.awt.BorderLayout;
import java.awt.Dimension;
import java.awt.FlowLayout;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.util.ArrayList;
import java.util.Vector;

import javax.swing.BorderFactory;
import javax.swing.JButton;
import javax.swing.JComboBox;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.ListSelectionModel;
import javax.swing.table.DefaultTableModel;

import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;

@SuppressWarnings("serial")
public class CertificationRequestsPanel extends CustomJPanelAdapter {

	private UI mUI;
	
	private CustomJTableAdapter certificationRequestsTable;
	private DefaultTableModel certificationRequestsTableModel;

	public CertificationRequestsPanel(UI ui) {
		mUI = ui;
		
		setLayout(new BorderLayout());
		
		JPanel pendingCertificationRequests = new JPanel();
		pendingCertificationRequests.setLayout(new BorderLayout());
		pendingCertificationRequests.setBorder(BorderFactory.createTitledBorder("Pending certification requests"));
		
		certificationRequestsTableModel = new DefaultTableModel();
		updateTablesData();

		certificationRequestsTable = new CustomJTableAdapter(certificationRequestsTableModel);
		certificationRequestsTable.setFillsViewportHeight(true);
		certificationRequestsTable.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
		certificationRequestsTable.setColumnSelectionAllowed(false);
		certificationRequestsTable.setCustomScrollableViewportSize();
		
		JButton checkCertificationRequestButton = new JButton("Check certification request");
		checkCertificationRequestButton.setSize(new Dimension(200, 20));
		checkCertificationRequestButton.addActionListener(new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent arg0) {
				int row = certificationRequestsTable.getSelectedRow();
				
				if (row == -1) {
					JOptionPane.showMessageDialog(mUI, "Please select a certification request from the table!");
				}
				int requestID = Integer.valueOf((String) certificationRequestsTableModel.getValueAt(row, 0));
				
				Integer id = mUI.getClient().checkCertificateRequest(requestID);
				if (id != null) {
					int type = Integer.valueOf((String) certificationRequestsTableModel.getValueAt(row, 3));
					if (type == KeyUsage.digitalSignature)
						mUI.setActiveDigitalSignatureCertificate(id);
					else mUI.setActiveDataEnciphermentCertificate(id);
					
					mUI.getCertificatesPanel().updateTablesData();
					updateTablesData();
					revalidate();
				} else JOptionPane.showMessageDialog(mUI, "Request not processed yet");
			}
		});
		
		JScrollPane scrollPane = new JScrollPane(certificationRequestsTable);

		pendingCertificationRequests.add(scrollPane);
		
		JPanel askForNewCertificatePanel = new JPanel();
		askForNewCertificatePanel.setLayout(new FlowLayout());
		askForNewCertificatePanel.setBorder(BorderFactory.createTitledBorder("New certificate requests"));
		
		final JComboBox keyLengthBox = new JComboBox(new String[] {"1024", "1536", "2048"});
		final JComboBox typeBox = new JComboBox(new String[] {"digital signature", "data encryption"});
		
		JButton askCertificate = new JButton("Ask certificate");
		askCertificate.addActionListener(new ActionListener() {
			@SuppressWarnings("unchecked")
			@Override
			public void actionPerformed(ActionEvent event) {
				String length = (String) keyLengthBox.getSelectedItem();
				String type = (String) typeBox.getSelectedItem();
				
				Vector<Vector<String>> outerVector = certificationRequestsTableModel.getDataVector();
				
				if (type.contains("digital")) {
					if (mUI.getActiveDigitalSignatureCertificate() == null) {
						boolean isDigital = false;
						for (Vector<String> innerVector : outerVector) {
							if (innerVector.get(3).startsWith("128"))
								isDigital = true;
						}
						
						if (!isDigital)
							mUI.getClient().generateCertificateRequest(length, new KeyUsage(KeyUsage.digitalSignature));
						else JOptionPane.showMessageDialog(mUI, "You already have a pending request for a digital signature certificate!");
					}
					else JOptionPane.showMessageDialog(mUI, "You already have a valid certificate for digital signature!");
 
				}
				else
					if (mUI.getActiveDataEnciphermentCertificate() == null)
						if (mUI.getActiveDigitalSignatureCertificate() != null) {
							boolean isEncipherment = false;
							for (Vector<String> innerVector : outerVector) {
								if (innerVector.get(3).startsWith("16"))
									isEncipherment = true;
							}
							
							if (!isEncipherment)
								mUI.getClient().generateCertificateRequest(length, new KeyUsage(KeyUsage.dataEncipherment));
							else JOptionPane.showMessageDialog(mUI, "You already have a pending request for a data encipherment certificate!");
						}
						else JOptionPane.showMessageDialog(mUI, "You already have a valid certificate for data encipherment!");
					else JOptionPane.showMessageDialog(mUI, "No valid digital signature certificate to perform the operation!");
				
				updateTablesData();
				revalidate();
			}
		});
		
		askForNewCertificatePanel.add(keyLengthBox);
		askForNewCertificatePanel.add(typeBox);
		askForNewCertificatePanel.add(askCertificate);
		
		JPanel container = new JPanel();
		container.setLayout(new BorderLayout());
		container.add(checkCertificationRequestButton, BorderLayout.NORTH);
		container.add(askForNewCertificatePanel, BorderLayout.SOUTH);
		
		add(pendingCertificationRequests, BorderLayout.NORTH);
		add(container, BorderLayout.SOUTH);
	}
	
	public void updateTablesData() {
		Vector<String> columnNames = new Vector<String>();
		columnNames.add("RequestID");
		columnNames.add("ServerID");
		columnNames.add("Subject");
		columnNames.add("Type");
		columnNames.add("Public Key");
		
		Vector<Vector<String>> tableContent = new Vector<Vector<String>>();
		
		ArrayList<PKCS10CertificationRequest> certificationRequestsList = mUI.getClient().getCertificationRequestsList();
		ArrayList<Integer[]> certificationRequestsDetailsList = mUI.getClient().getCertificationRequestsDetailsList();
		
		for (int i=0; i<certificationRequestsList.size(); i++) {
			PKCS10CertificationRequest request = certificationRequestsList.get(i);
			Integer[] details = certificationRequestsDetailsList.get(i);
			
			Vector<String> row = new Vector<String>();
			
			row.add(details[0].toString());
			row.add(details[1].toString());
			row.add(request.getSubject().toString());
			row.add(details[2].toString());
			row.add(request.getSubjectPublicKeyInfo().getPublicKeyData().getString());
			
			tableContent.add(row);
		}

		certificationRequestsTableModel.setDataVector(tableContent, columnNames);
		certificationRequestsTableModel.fireTableDataChanged();
	}

	@Override
	public void updateData() {
		updateTablesData();
	}
}
