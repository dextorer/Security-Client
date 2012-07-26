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
import java.util.Date;
import java.util.HashMap;

import javax.swing.BorderFactory;
import javax.swing.Box;
import javax.swing.BoxLayout;
import javax.swing.GroupLayout;
import javax.swing.GroupLayout.Alignment;
import javax.swing.JButton;
import javax.swing.JFileChooser;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JTextField;
import javax.swing.border.EmptyBorder;
import javax.swing.filechooser.FileFilter;
import javax.swing.filechooser.FileNameExtensionFilter;

import com.itextpdf.text.pdf.PdfReader;

@SuppressWarnings("serial")
public class PDFSignaturePanel extends CustomJPanelAdapter {

	private UI mUI;
	
	private JPanel PDFPanel;
	private JPanel PDFActionPanel;
	
	private JButton choosePDFButton;
	private JTextField PDFPath;
	
	private JTextField titleField;
	private JTextField authorField;
	private JTextField createdField;
	private JTextField modifiedField;
	private JTextField pagesField;
	private JTextField producerField;

	private JButton signPDFButton;
	private JButton verifyPDFButton;
	private JTextField logTextField;
	
	public PDFSignaturePanel(UI ui) {
		mUI = ui;
		PDFPath = new JTextField("PDF path");
		PDFPath.setHorizontalAlignment(JTextField.CENTER);
		PDFPath.setEditable(false);
		
		logTextField = new JTextField();
		logTextField.setEditable(false);
		logTextField.setHorizontalAlignment(JTextField.CENTER);
		
		PDFPanel = new JPanel();
		PDFPanel.setLayout(new BorderLayout());
		
		JPanel detailsPanel = createPDFDetailsPanel();
		detailsPanel.setBorder(BorderFactory.createTitledBorder("PDF Details"));
		
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
				logTextField.setText("");
				int result = chooser.showOpenDialog(PDFPanel);
				if (result == JFileChooser.APPROVE_OPTION) {
					File chosen = chooser.getSelectedFile();
					PDFPath.setText(chosen.getAbsolutePath());
					updatePDFInfo(chosen);
				}
			}
		});
		
		choosePanel.add(PDFPath);
		choosePanel.add(Box.createHorizontalStrut(10));
		choosePanel.add(choosePDFButton);
		
		PDFPanel.add(detailsPanel, BorderLayout.CENTER);
		PDFPanel.add(choosePanel, BorderLayout.SOUTH);
		
		PDFActionPanel = new JPanel();
		PDFActionPanel.setLayout(new FlowLayout());
		
		signPDFButton = new JButton("Sign PDF");
		signPDFButton.addActionListener(new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent event) {
				String path = PDFPath.getText();
				if (path.length() > 0 && path.endsWith(".pdf")) {
					try {
						mUI.getClient().signPDF(path);
						logTextField.setText("PDF correctly signed!");
						PDFPath.setText("");
						mUI.update(mUI.getGraphics());
					} catch (Exception e) {
						e.printStackTrace();
						logTextField.setText(e.getMessage());
					}
				}
				else logTextField.setText("Select a PDF file first!");
			}
		});
		
		verifyPDFButton = new JButton("Verify PDF");
		verifyPDFButton.addActionListener(new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent event) {
				String path = PDFPath.getText();
				if (path.length() > 0 && path.endsWith(".pdf")) {
					try {
						mUI.getClient().verifyPDF(path);
						logTextField.setText("PDF signature is valid!");
						PDFPath.setText("");
						mUI.update(mUI.getGraphics());
					} catch (Exception e) {
						e.printStackTrace();
						logTextField.setText(e.getMessage());
					}
				}
				else logTextField.setText("Select a PDF file first!");
			}
		});

		PDFActionPanel.add(signPDFButton);
		PDFActionPanel.add(verifyPDFButton);
		PDFActionPanel.add(logTextField);
		
		setLayout(new BorderLayout());
		setBorder(new EmptyBorder(10, 10, 10, 10));
		add(PDFPanel, BorderLayout.CENTER);
		add(PDFActionPanel, BorderLayout.SOUTH);
	}

	private void updatePDFInfo(File pdf) {
		try {
			PdfReader reader = new PdfReader(pdf.getAbsolutePath());
			HashMap<String, String> info = reader.getInfo();
			
			DateFormat format = new SimpleDateFormat("yyyyMMddHHmmssZ");
			if (info.get("CreationDate") != null) {
				Date created = format.parse(info.get("CreationDate").replace("D:", "").replace("'", ""));
				createdField.setText(created.toString());
			}
			if (info.get("ModDate") != null) {
				Date modified = format.parse(info.get("ModDate").replace("D:", "").replace("'", ""));
				modifiedField.setText(modified.toString());
			}
			
			titleField.setText(info.get("Title"));
			authorField.setText(info.get("Author"));
			pagesField.setText(String.valueOf(reader.getNumberOfPages()));
			producerField.setText(info.get("Producer"));
			
		} catch (IOException e) {
			e.printStackTrace();
		} catch (ParseException e) {
			e.printStackTrace();
		}
		
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
	public void updateData() {}
	
}
