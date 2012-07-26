package org.megadevs.security.client.ui;

import java.awt.BorderLayout;

import javax.swing.BorderFactory;
import javax.swing.GroupLayout;
import javax.swing.GroupLayout.Alignment;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JTextField;

import org.megadevs.security.client.ui.wizard.WizardPanelDescriptor;

public class InsertInfromationsWizardPanel extends WizardPanelDescriptor {
	
	public static String IDENTIFIER = "insert_informations";
	
	private JTextField surnameField;
	private JTextField nameField;
	private JTextField organizationField;
	private JTextField organizationalUnitField;
	private JTextField countryField;
	private JTextField emailField;
	
	public InsertInfromationsWizardPanel() {
		setPanelComponent(createPanel());
		setPanelDescriptorIdentifier(IDENTIFIER);
	}

	private JPanel createPanel() {
		JPanel panel = new JPanel();
		panel.setLayout(new BorderLayout());
		
		JLabel text = new JLabel();
		text.setText("Please complete the following information fields.");
		
		JPanel dataPanel = new JPanel();
		dataPanel.setBorder(BorderFactory.createTitledBorder("Client informations"));
		
		surnameField = new JTextField();
		nameField = new JTextField();
		organizationField = new JTextField();
		organizationalUnitField = new JTextField();
		countryField = new JTextField();
		emailField = new JTextField();
		
		JLabel surnameLabel = new JLabel("Surname");
		JLabel nameLabel = new JLabel("Name");
		JLabel organizationLabel = new JLabel("Organization");
		JLabel organizationalUnitLabel = new JLabel("Organizational Unit");
		JLabel countryLabel = new JLabel("Country");
		JLabel emailLabel = new JLabel("E-mail");
		
		GroupLayout myDataLayout = new GroupLayout(dataPanel);
		dataPanel.setLayout(myDataLayout);
		myDataLayout.setAutoCreateGaps(true);

		GroupLayout.SequentialGroup hGroup = myDataLayout.createSequentialGroup();

		GroupLayout.ParallelGroup pGroup1 = myDataLayout.createParallelGroup();
		GroupLayout.ParallelGroup pGroup2 = myDataLayout.createParallelGroup();

		pGroup1.addComponent(surnameLabel).addComponent(nameLabel);
		pGroup1.addComponent(organizationLabel).addComponent(organizationalUnitLabel);
		pGroup1.addComponent(countryLabel).addComponent(emailLabel);

		hGroup.addGroup(pGroup1);

		pGroup2.addComponent(surnameField).addComponent(nameField);
		pGroup2.addComponent(organizationField).addComponent(organizationalUnitField);
		pGroup2.addComponent(countryField).addComponent(emailField);

		hGroup.addGroup(pGroup2);

		myDataLayout.setHorizontalGroup(hGroup);

		GroupLayout.SequentialGroup vGroup = myDataLayout.createSequentialGroup();

		vGroup.addGroup(myDataLayout.createParallelGroup(Alignment.BASELINE)
				.addComponent(surnameLabel).addComponent(surnameField));
		vGroup.addGroup(myDataLayout.createParallelGroup(Alignment.BASELINE)
				.addComponent(nameLabel).addComponent(nameField));
		vGroup.addGroup(myDataLayout.createParallelGroup(Alignment.BASELINE)
				.addComponent(organizationLabel).addComponent(organizationField));
		vGroup.addGroup(myDataLayout.createParallelGroup(Alignment.BASELINE)
				.addComponent(organizationalUnitLabel).addComponent(organizationalUnitField));
		vGroup.addGroup(myDataLayout.createParallelGroup(Alignment.BASELINE)
				.addComponent(countryLabel).addComponent(countryField));
		vGroup.addGroup(myDataLayout.createParallelGroup(Alignment.BASELINE)
				.addComponent(emailLabel).addComponent(emailField));

		myDataLayout.setVerticalGroup(vGroup);

		panel.add(text,BorderLayout.NORTH);
		panel.add(dataPanel, BorderLayout.CENTER);
		
		return panel;
	}
	
	@Override
	public Object getBackPanelDescriptor() {
		return InsertPasswordWizardPanel.IDENTIFIER;
	}
	
	@Override
	public Object getNextPanelDescriptor() {
		if (!surnameField.getText().equals("") && 
				!nameField.getText().equals("") && 
				!organizationField.getText().equals("") && 
				!organizationalUnitField.getText().equals("") && 
				!countryField.getText().equals("") && 
				!emailField.getText().equals(""))
			return InsertKeyLengthWizardPanel.IDENTIFIER;
		else return InsertInfromationsWizardPanel.IDENTIFIER;
	}

	public String getSurname() {
		return surnameField.getText();
	}

	public String getName() {
		return nameField.getText();
	}

	public String getOrganization() {
		return organizationField.getText();
	}

	public String getOrganizationalUnit() {
		return organizationalUnitField.getText();
	}

	public String getCountry() {
		return countryField.getText();
	}

	public String getEmail() {
		return emailField.getText();
	}
}
