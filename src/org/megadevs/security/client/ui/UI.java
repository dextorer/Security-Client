package org.megadevs.security.client.ui;

import java.awt.BorderLayout;
import java.awt.Dimension;
import java.awt.FlowLayout;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.util.ArrayList;

import javax.swing.BorderFactory;
import javax.swing.GroupLayout;
import javax.swing.GroupLayout.Alignment;
import javax.swing.JButton;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JPasswordField;
import javax.swing.JTabbedPane;
import javax.swing.event.ChangeEvent;
import javax.swing.event.ChangeListener;

import org.bouncycastle.asn1.x509.KeyUsage;
import org.megadevs.security.client.Client;
import org.megadevs.security.client.ui.wizard.Wizard;

@SuppressWarnings("serial")
public class UI extends JFrame {

	private Client mClient;
	
	private JPanel showPasswordPanel;
	
	private CertificationRequestsPanel certificationRequestsPanel;
	private CertificatesPanel certificatesPanel;
	private ProfilePanel profilePanel;
	private CRLPanel crlPanel;
	
	private PDFSignaturePanel pdfSignaturePanel;
	private PDFEncryptionPanel pdfEncriptionPanel;
	private PDFDecryptionPanel pdfDecryptionPanel;
	
	private Wizard mWizard;
	
	private Integer activeDigitalSignatureCertificate;
	private Integer activeDataEnciphermentCertificate;
	
	public UI(Client client, boolean dbExists) {
		mClient = client;
		setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
		setLocationRelativeTo(null);
		
		if (dbExists)
			showPasswordPrompt();
		else {
			startWizard();
			createMainPanel();
		}
	}
	
	private void showPasswordPrompt() {
		setTitle("Sicurezza - Client");
		showPasswordPanel = new JPanel();
		showPasswordPanel.setLayout(new BorderLayout());
		
		JLabel description = new JLabel();
		description.setText("Please insert a password for the client application.");
		
		JPanel passwordPanel = new JPanel();
		passwordPanel.setLayout(new FlowLayout());
		passwordPanel.setBorder(BorderFactory.createTitledBorder("Password"));
		
		JLabel insertPasswordLabel = new JLabel("Insert password");
		JLabel confirmPasswordLabel = new JLabel("Confirm password");
		
		final JPasswordField insertPasswordField = new JPasswordField();
		final JPasswordField confirmPasswordField = new JPasswordField();
		
		GroupLayout myDataLayout = new GroupLayout(passwordPanel);
		passwordPanel.setLayout(myDataLayout);
		myDataLayout.setAutoCreateGaps(true);

		GroupLayout.SequentialGroup hGroup = myDataLayout.createSequentialGroup();

		GroupLayout.ParallelGroup pGroup1 = myDataLayout.createParallelGroup();
		GroupLayout.ParallelGroup pGroup2 = myDataLayout.createParallelGroup();

		pGroup1.addComponent(insertPasswordLabel).addComponent(confirmPasswordLabel);
		hGroup.addGroup(pGroup1);

		pGroup2.addComponent(insertPasswordField).addComponent(confirmPasswordField);
		hGroup.addGroup(pGroup2);

		myDataLayout.setHorizontalGroup(hGroup);

		GroupLayout.SequentialGroup vGroup = myDataLayout.createSequentialGroup();

		vGroup.addGroup(myDataLayout.createParallelGroup(Alignment.BASELINE)
				.addComponent(insertPasswordLabel).addComponent(insertPasswordField));
		vGroup.addGroup(myDataLayout.createParallelGroup(Alignment.BASELINE)
				.addComponent(confirmPasswordLabel).addComponent(confirmPasswordField));

		myDataLayout.setVerticalGroup(vGroup);
		
		JButton confirm = new JButton("Confirm");
		confirm.addActionListener(new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent event) {
				int insertLength = insertPasswordField.getPassword().length;
				int confirmLength = confirmPasswordField.getPassword().length;
				if (insertLength != 0 && insertLength == confirmLength) {
					boolean isValid = mClient.checkPassword(new String(insertPasswordField.getPassword()));
					if (isValid) {
						try {
							mClient.init();
						} catch (Exception e) {
							noValidDigitalSignatureCertificate();
						}
						createMainPanel();
					}
					else {
						JOptionPane.showMessageDialog(UI.this, "Wrong password. Please try again!");
						insertPasswordField.setText("");
						confirmPasswordField.setText("");
					}
				}
				else {
					JOptionPane.showMessageDialog(UI.this, "Passwords do not match!");
					insertPasswordField.setText("");
					confirmPasswordField.setText("");
				}
			}
		});
		
		showPasswordPanel.add(description, BorderLayout.NORTH);
		showPasswordPanel.add(passwordPanel, BorderLayout.CENTER);
		showPasswordPanel.add(confirm, BorderLayout.SOUTH);

		setContentPane(showPasswordPanel);
		pack();
		setLocationRelativeTo(null);
		setVisible(true);
	}

	public void noValidDigitalSignatureCertificate() {
		String message = "No valid digital signature certificates were found. Please select a keylength for an automatic new request";
		String length = (String) JOptionPane.showInputDialog(UI.this, message, "No valid Digital Signature certificates", JOptionPane.ERROR_MESSAGE, null, new String[] {"1024", "1536", "2048"}, "1024");
		mClient.createFirstRequest(length);
	}
	
	private void createMainPanel() {
		activeDigitalSignatureCertificate = mClient.getActiveCertificate(new KeyUsage(KeyUsage.digitalSignature), false);
		activeDataEnciphermentCertificate = mClient.getActiveCertificate(new KeyUsage(KeyUsage.dataEncipherment), false);

		certificationRequestsPanel = new CertificationRequestsPanel(this);
		certificatesPanel = new CertificatesPanel(this);
		profilePanel = new ProfilePanel(this);
		crlPanel = new CRLPanel(this);
		pdfSignaturePanel = new PDFSignaturePanel(this);
		pdfEncriptionPanel = new PDFEncryptionPanel(this);
		pdfDecryptionPanel = new PDFDecryptionPanel(this);
		
		final JTabbedPane pane = new JTabbedPane();
		pane.setTabLayoutPolicy(JTabbedPane.WRAP_TAB_LAYOUT);
		pane.addTab("Certification Requests", certificationRequestsPanel);
		pane.addTab("Certificates", certificatesPanel);
		pane.addTab("Profile", profilePanel);
		pane.addTab("CRL", crlPanel);
		pane.addTab("PDF Signature", pdfSignaturePanel);
		pane.addTab("PDF Encryption", pdfEncriptionPanel);
		pane.addTab("PDF Decryption", pdfDecryptionPanel);
		
		pane.addChangeListener(new ChangeListener() {
			@Override
			public void stateChanged(ChangeEvent event) {
				JTabbedPane source = (JTabbedPane) event.getSource();
				CustomJPanelAdapter panel = (CustomJPanelAdapter) source.getSelectedComponent();
				panel.updateData();
			}
		});
		
		ArrayList<String> clientInfo = mClient.getClientInfo();
		setTitle(clientInfo.get(1) + " " + clientInfo.get(0) + " " + clientInfo.get(5) + " - " + getTitle());
		
		setContentPane(pane);
		validate();
		pack();
		setLocationRelativeTo(null);
		setVisible(true);
	}

	private void startWizard() {
		mWizard = new Wizard(this);
		mWizard.getDialog().setResizable(false);
		mWizard.getDialog().setMaximumSize(new Dimension(300, 200));
		
		InsertPasswordWizardPanel password = new InsertPasswordWizardPanel();
		mWizard.registerWizardPanel(InsertPasswordWizardPanel.IDENTIFIER, password);
		
		InsertInfromationsWizardPanel info = new InsertInfromationsWizardPanel();
		mWizard.registerWizardPanel(InsertInfromationsWizardPanel.IDENTIFIER, info);
		
		InsertKeyLengthWizardPanel key = new InsertKeyLengthWizardPanel();
		mWizard.registerWizardPanel(InsertKeyLengthWizardPanel.IDENTIFIER, key);
		
		mWizard.setCurrentPanel(InsertPasswordWizardPanel.IDENTIFIER);
		int exitCode = mWizard.showModalDialog();
		
		if (exitCode == Wizard.FINISH_RETURN_CODE) {
			String pw = password.getPassword();
			
			String surname = info.getSurname();
			String name = info.getName();
			String organization = info.getOrganization();
			String organizationalUnit = info.getOrganizationalUnit();
			String country = info.getCountry();
			String email = info.getEmail();
			
			String keyLength = key.getKeyLength();
			
			mClient.setAndStoreClientPassword(pw);
			mClient.storeClientInfo(surname, name, organization, organizationalUnit, country, email);
			mClient.createFirstRequest(keyLength);
		}
		
	}

	public Client getClient() {
		return mClient;
	}

	public Integer getActiveDigitalSignatureCertificate() {
		return activeDigitalSignatureCertificate;
	}

	public Integer getActiveDataEnciphermentCertificate() {
		return activeDataEnciphermentCertificate;
	}

	public void setActiveDigitalSignatureCertificate(
			Integer activeDigitalSignatureCertificate) {
		this.activeDigitalSignatureCertificate = activeDigitalSignatureCertificate;
	}

	public void setActiveDataEnciphermentCertificate(
			Integer activeDataEnciphermentCertificate) {
		this.activeDataEnciphermentCertificate = activeDataEnciphermentCertificate;
	}

	public CertificationRequestsPanel getCertificationRequestsPanel() {
		return certificationRequestsPanel;
	}

	public CertificatesPanel getCertificatesPanel() {
		return certificatesPanel;
	}

	public CRLPanel getCrlPanel() {
		return crlPanel;
	}
}
