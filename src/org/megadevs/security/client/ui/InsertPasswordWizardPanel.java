package org.megadevs.security.client.ui;

import java.awt.BorderLayout;
import java.awt.FlowLayout;

import javax.swing.BorderFactory;
import javax.swing.GroupLayout;
import javax.swing.GroupLayout.Alignment;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JPasswordField;

import org.megadevs.security.client.ui.wizard.WizardPanelDescriptor;

public class InsertPasswordWizardPanel extends WizardPanelDescriptor {

	public static String IDENTIFIER = "insert_password";
	
	private JPasswordField insertPasswordField;
	private JPasswordField confirmPasswordField;
	
	public InsertPasswordWizardPanel() {
		setPanelComponent(createPanel());
		setPanelDescriptorIdentifier(IDENTIFIER);
	}
	
	private JPanel createPanel() {
		JPanel panel = new JPanel();
		panel.setLayout(new BorderLayout());
		
		JLabel description = new JLabel();
		description.setText("Please insert a password for the client application.");
		
		JPanel passwordPanel = new JPanel();
		passwordPanel.setLayout(new FlowLayout());
		passwordPanel.setBorder(BorderFactory.createTitledBorder("Password"));
		
		JLabel insertPasswordLabel = new JLabel("Insert password");
		JLabel confirmPasswordLabel = new JLabel("Confirm password");
		
		insertPasswordField = new JPasswordField();
		confirmPasswordField = new JPasswordField();
		
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
		
		panel.add(description, BorderLayout.NORTH);
		panel.add(passwordPanel, BorderLayout.CENTER);
		
		return panel;
	}
	
	public String getPassword() {
		return new String(insertPasswordField.getPassword());
	}
	
	@Override
	public Object getBackPanelDescriptor() {
		return null;
	}
	
	@Override
	public Object getNextPanelDescriptor() {
		char[] password = insertPasswordField.getPassword(); 
		char[] confirm = confirmPasswordField.getPassword();

		String s1 = new String(password);
		String s2 = new String(confirm);
		
		if (s1.length() > 0 && s2.length() >0 && s1.compareTo(s2) == 0)
			return InsertInfromationsWizardPanel.IDENTIFIER;
		else return InsertPasswordWizardPanel.IDENTIFIER;
	}
	
}
