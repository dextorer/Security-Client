package org.megadevs.security.client.ui;

import java.awt.BorderLayout;
import java.awt.FlowLayout;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.File;
import java.io.IOException;
import java.text.DateFormat;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashMap;
import java.util.Vector;

import javax.swing.BorderFactory;
import javax.swing.Box;
import javax.swing.BoxLayout;
import javax.swing.GroupLayout;
import javax.swing.GroupLayout.Alignment;
import javax.swing.JButton;
import javax.swing.JFileChooser;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTable;
import javax.swing.JTextField;
import javax.swing.ListSelectionModel;
import javax.swing.filechooser.FileFilter;
import javax.swing.filechooser.FileNameExtensionFilter;
import javax.swing.table.DefaultTableModel;

import org.megadevs.security.client.pdf.PDFUtils;

@SuppressWarnings("serial")
public class PDFDecryptionPanel extends CustomJPanelAdapter {

	private UI mUI;
	
	private JScrollPane availableCertificatesPanel;

	private JButton choosePDFButton;
	private JTextField PDFPath;

	private JPanel PDFPanel;
	private JPanel decryptionActionPanel;
	
	private JButton decryptButton;
	
	private JTable availableCertificatesTable;
	private DefaultTableModel availableCertificatesTableModel;
	
	private JTextField titleField;
	private JTextField authorField;
	private JTextField createdField;
	private JTextField modifiedField;
	private JTextField pagesField;
	private JTextField producerField;
	
	private JTextField logTextField;

	public PDFDecryptionPanel(UI ui) {
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
		
		JPanel detailsPanel = createPDFDetailsPanel();
		detailsPanel.setBorder(BorderFactory.createTitledBorder("Certificate Details"));
		PDFPanel.add(detailsPanel, BorderLayout.NORTH);
		PDFPanel.add(choosePanel, BorderLayout.SOUTH);

		availableCertificatesTableModel = new DefaultTableModel();
		updateData();
		
		availableCertificatesTable = new CustomJTableAdapter(availableCertificatesTableModel);
		availableCertificatesTable.setFillsViewportHeight(false);
		availableCertificatesTable.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
		availableCertificatesTable.setColumnSelectionAllowed(false);

		availableCertificatesPanel = new JScrollPane(availableCertificatesTable, JScrollPane.VERTICAL_SCROLLBAR_AS_NEEDED, JScrollPane.HORIZONTAL_SCROLLBAR_NEVER);
		availableCertificatesPanel.setBorder(BorderFactory.createTitledBorder("Active certificates"));
		
		decryptionActionPanel = new JPanel();
		decryptionActionPanel.setLayout(new FlowLayout());

		decryptButton = new JButton("Decrypt PDF");
		decryptButton.addActionListener(new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent arg0) {
				if (!availableCertificatesTable.getSelectionModel().isSelectionEmpty()) {
					int row = availableCertificatesTable.getSelectedRow();
					Integer ID = new Integer((String) availableCertificatesTableModel.getValueAt(row, 0));
					
					String path = PDFPath.getText();
					if (path.length() > 0 && path.endsWith(".pdf")) {
						String result = mUI.getClient().decryptPDF(path, ID);
						logTextField.setText(result);
						revalidate();
					}
				} else JOptionPane.showMessageDialog(decryptionActionPanel, "You must select a certificate first!");
			}
		});
		
		decryptionActionPanel.add(decryptButton);
		decryptionActionPanel.add(logTextField);
		
		add(PDFPanel, BorderLayout.NORTH);
		add(availableCertificatesPanel, BorderLayout.CENTER);
		add(decryptionActionPanel, BorderLayout.SOUTH);
	}
	
	private void updateTablesData() {
		Vector<String> columnNames = new Vector<String>();
		columnNames.add("Serial");
		columnNames.add("Serial CA");
		columnNames.add("Not before");
		columnNames.add("Not after");
		columnNames.add("Renewed");
		
		final ArrayList<Object[]> availableDetails = mUI.getClient().getCertificatesDetailsList();
		Vector<Vector<String>> available = new Vector<Vector<String>>();
		for (Object[] data : availableDetails) {
			Integer type = (Integer) data[5];
			if (type.intValue() == 16) {
				Vector<String> availableRow = new Vector<String>();
				availableRow.add(((Integer) data[0]).toString());
				availableRow.add(((Integer) data[1]).toString());
				availableRow.add(((Date) data[2]).toString());
				availableRow.add(((Date) data[3]).toString());
				availableRow.add(((Integer) data[6]).toString());
				available.add(availableRow);
			}
		}
		
		availableCertificatesTableModel.setDataVector(available, columnNames);
		availableCertificatesTableModel.fireTableDataChanged();
	}
	
	private JPanel createPDFDetailsPanel() {
		JPanel panel = new JPanel();
		
		titleField = new JTextField("");
		titleField.setEditable(false);
		titleField.setHorizontalAlignment(JTextField.CENTER);
		authorField = new JTextField("");
		authorField.setEditable(false);
		authorField.setHorizontalAlignment(JTextField.CENTER);
		createdField = new JTextField("");
		createdField.setEditable(false);
		createdField.setHorizontalAlignment(JTextField.CENTER);
		modifiedField = new JTextField("");
		modifiedField.setEditable(false);
		modifiedField.setHorizontalAlignment(JTextField.CENTER);
		pagesField = new JTextField("");
		pagesField.setEditable(false);
		pagesField.setHorizontalAlignment(JTextField.CENTER);
		producerField = new JTextField("");
		producerField.setEditable(false);
		producerField.setHorizontalAlignment(JTextField.CENTER);
		
		JLabel titleLabel = new JLabel("Title");
		JLabel authorLabel = new JLabel("Author");
		JLabel createdLabel = new JLabel("Created");
		JLabel modifiedLabel = new JLabel("Modified");
		JLabel pagesLabel = new JLabel("Number of pages");
		JLabel producerLabel = new JLabel("Producer");
		
		GroupLayout myDataLayout = new GroupLayout(panel);
		panel.setLayout(myDataLayout);
		myDataLayout.setAutoCreateGaps(true);

		GroupLayout.SequentialGroup hGroup = myDataLayout.createSequentialGroup();

		GroupLayout.ParallelGroup pGroup1 = myDataLayout.createParallelGroup();
		GroupLayout.ParallelGroup pGroup2 = myDataLayout.createParallelGroup();

		pGroup1.addComponent(titleLabel).addComponent(authorLabel);
		pGroup1.addComponent(createdLabel).addComponent(pagesLabel);
		pGroup1.addComponent(producerLabel).addComponent(modifiedLabel);

		hGroup.addGroup(pGroup1);

		pGroup2.addComponent(titleField).addComponent(authorField);
		pGroup2.addComponent(createdField).addComponent(modifiedField);
		pGroup2.addComponent(pagesField).addComponent(producerField);

		hGroup.addGroup(pGroup2);

		myDataLayout.setHorizontalGroup(hGroup);

		GroupLayout.SequentialGroup vGroup = myDataLayout.createSequentialGroup();

		vGroup.addGroup(myDataLayout.createParallelGroup(Alignment.BASELINE)
				.addComponent(titleLabel).addComponent(titleField));
		vGroup.addGroup(myDataLayout.createParallelGroup(Alignment.BASELINE)
				.addComponent(authorLabel).addComponent(authorField));
		vGroup.addGroup(myDataLayout.createParallelGroup(Alignment.BASELINE)
				.addComponent(createdLabel).addComponent(createdField));
		vGroup.addGroup(myDataLayout.createParallelGroup(Alignment.BASELINE)
				.addComponent(pagesLabel).addComponent(pagesField));
		vGroup.addGroup(myDataLayout.createParallelGroup(Alignment.BASELINE)
				.addComponent(producerLabel).addComponent(producerField));
		vGroup.addGroup(myDataLayout.createParallelGroup(Alignment.BASELINE)
				.addComponent(modifiedLabel).addComponent(modifiedField));

		myDataLayout.setVerticalGroup(vGroup);

		return panel;
	}

	@Override
	public void updateData() {
		updateTablesData();
	}
}
