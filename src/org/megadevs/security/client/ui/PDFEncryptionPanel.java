package org.megadevs.security.client.ui;

import java.awt.BorderLayout;
import java.awt.FlowLayout;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.File;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Vector;

import javax.swing.BorderFactory;
import javax.swing.Box;
import javax.swing.BoxLayout;
import javax.swing.JButton;
import javax.swing.JComboBox;
import javax.swing.JFileChooser;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTable;
import javax.swing.JTextField;
import javax.swing.ListSelectionModel;
import javax.swing.filechooser.FileFilter;
import javax.swing.filechooser.FileNameExtensionFilter;
import javax.swing.table.DefaultTableModel;

import org.bouncycastle.cert.X509CertificateHolder;

@SuppressWarnings("serial")
public class PDFEncryptionPanel extends CustomJPanelAdapter {

	private UI mUI;
	
	private JScrollPane availableCertificatesPanel;

	private JButton choosePDFButton;
	private JTextField PDFPath;

	private JPanel PDFPanel;
	private JPanel encryptionActionPanel;
	
	private JComboBox encryptionChooserBox;
	private JButton encryptButton;
	
	private ArrayList<X509CertificateHolder> availableDetails;
	
	private JTable availableCertificatesTable;
	private DefaultTableModel availableCertificatesTableModel;

	private JTextField logTextField;
	
	public PDFEncryptionPanel(UI ui) {
		mUI = ui;
		setLayout(new BorderLayout());
		
		PDFPanel = new JPanel();
		PDFPanel.setLayout(new BorderLayout());
		
		PDFPath = new JTextField();
		PDFPath.setEditable(false);
		
		logTextField = new JTextField();
		logTextField.setEditable(false);
		logTextField.setHorizontalAlignment(JTextField.CENTER);
		
		JPanel choosePanel = new JPanel();
		choosePanel.setLayout(new BoxLayout(choosePanel, BoxLayout.X_AXIS));
		choosePanel.setBorder(BorderFactory.createTitledBorder("PDF file chooser"));
		
		choosePDFButton = new JButton("Choose PDF..");
		choosePDFButton.addActionListener(new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent arg0) {
				JFileChooser chooser = new JFileChooser("~");
				chooser.setFileSelectionMode(JFileChooser.FILES_ONLY);
				FileFilter filter = new FileNameExtensionFilter("PDF file", "pdf");
				chooser.setFileFilter(filter);
				int result = chooser.showOpenDialog(PDFPanel);
				if (result == JFileChooser.APPROVE_OPTION) {
					File chosen = chooser.getSelectedFile();
					PDFPath.setText(chosen.getAbsolutePath());
					logTextField.setText("");
					revalidate();
				}
			}
		});
		
		choosePanel.add(PDFPath);
		choosePanel.add(Box.createHorizontalStrut(10));
		choosePanel.add(choosePDFButton);
		
		PDFPanel.add(choosePanel, BorderLayout.SOUTH);

		availableCertificatesTableModel = new DefaultTableModel();
		updateData();
		
		availableCertificatesTable = new JTable(availableCertificatesTableModel) {
			public boolean isCellEditable(int row, int column) {
				return false;
			}
		};
		availableCertificatesTable.setFillsViewportHeight(true);
		availableCertificatesTable.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
		availableCertificatesTable.setColumnSelectionAllowed(false);

		availableCertificatesPanel = new JScrollPane(availableCertificatesTable, JScrollPane.VERTICAL_SCROLLBAR_AS_NEEDED, JScrollPane.HORIZONTAL_SCROLLBAR_NEVER);
		availableCertificatesPanel.setBorder(BorderFactory.createTitledBorder("Active certificates"));
		
		encryptionActionPanel = new JPanel();
		encryptionActionPanel.setLayout(new FlowLayout());

		encryptionChooserBox = new JComboBox(new String[] {"AES-128", "AES-256", "ARC4-40", "ARC4-128"});
		encryptButton = new JButton("Encrypt PDF");
		encryptButton.addActionListener(new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent arg0) {
				if (!availableCertificatesTable.getSelectionModel().isSelectionEmpty()) {
					int row = availableCertificatesTable.getSelectedRow();

					String encriptionType = (String) encryptionChooserBox.getSelectedItem();
					String path = PDFPath.getText();
					if (path.length() > 0 && path.endsWith(".pdf")) {
						String result = mUI.getClient().encryptPDF(path, encriptionType, availableDetails.get(row));
						logTextField.setText(result);
						revalidate();
					}
				}
				
			}
		});
		
		encryptionActionPanel.add(encryptionChooserBox);
		encryptionActionPanel.add(encryptButton);
		encryptionActionPanel.add(logTextField);
		
		add(choosePanel, BorderLayout.NORTH);
		add(availableCertificatesPanel, BorderLayout.CENTER);
		add(encryptionActionPanel, BorderLayout.SOUTH);
	}
	
	private void updateTablesData() {
		Vector<String> columnNames = new Vector<String>();
		columnNames.add("Surname");
		columnNames.add("Name");
		columnNames.add("Organization");
		columnNames.add("Organizational Unit");
		columnNames.add("Country");
		columnNames.add("E-mail");
		
		Vector<Vector<String>> available = new Vector<Vector<String>>();
		availableDetails = mUI.getClient().getActiveDataEnciphermentCertificates();
		if (availableDetails != null)
			for (X509CertificateHolder holder : availableDetails) {
				HashMap<String, String> fields = mUI.getClient().DNToProfile(holder.getSubject().toString());
				Vector<String> availableRow = new Vector<String>();
				availableRow.add(fields.get("SURNAME"));
				availableRow.add(fields.get("NAME"));
				availableRow.add(fields.get("O"));
				availableRow.add(fields.get("OU"));
				availableRow.add(fields.get("C"));
				availableRow.add(fields.get("EMAIL"));
				available.add(availableRow);
			}
		
		availableCertificatesTableModel.setDataVector(available, columnNames);
		availableCertificatesTableModel.fireTableDataChanged();

	}

	@Override
	public void updateData() {
		updateTablesData();
	}
}
