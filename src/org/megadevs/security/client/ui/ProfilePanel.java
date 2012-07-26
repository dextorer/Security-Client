package org.megadevs.security.client.ui;

import java.util.ArrayList;

import javax.swing.GroupLayout;
import javax.swing.GroupLayout.Alignment;
import javax.swing.JLabel;
import javax.swing.JTextField;
import javax.swing.border.EmptyBorder;

@SuppressWarnings("serial")
public class ProfilePanel extends CustomJPanelAdapter {

	private UI mUI;
	
	public ProfilePanel(UI ui) {
		mUI = ui;
		
		setBorder(new EmptyBorder(10, 10, 10, 10));
		
		ArrayList<String> profile = mUI.getClient().getClientInfo();
		
		JTextField surnameField = new JTextField(profile.get(0));
		surnameField.setEditable(false);
		surnameField.setHorizontalAlignment(JTextField.CENTER);
		JTextField nameField = new JTextField(profile.get(1));
		nameField.setEditable(false);
		nameField.setHorizontalAlignment(JTextField.CENTER);
		JTextField organizationField = new JTextField(profile.get(2));
		organizationField.setEditable(false);
		organizationField.setHorizontalAlignment(JTextField.CENTER);
		JTextField organizationalUnitField = new JTextField(profile.get(3));
		organizationalUnitField.setEditable(false);
		organizationalUnitField.setHorizontalAlignment(JTextField.CENTER);
		JTextField countryField = new JTextField(profile.get(4));
		countryField.setEditable(false);
		countryField.setHorizontalAlignment(JTextField.CENTER);
		JTextField emailField = new JTextField(profile.get(5));
		emailField.setEditable(false);
		emailField.setHorizontalAlignment(JTextField.CENTER);
		
		JLabel surnameLabel = new JLabel("Surname");
		JLabel nameLabel = new JLabel("Name");
		JLabel organizationLabel = new JLabel("Organization");
		JLabel organizationalUnitLabel = new JLabel("Organizational Unit");
		JLabel countryLabel = new JLabel("Country");
		JLabel emailLabel = new JLabel("E-mail");
		
		GroupLayout myDataLayout = new GroupLayout(this);
		setLayout(myDataLayout);
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
		
	}

	@Override
	public void updateData() {}
	
}
