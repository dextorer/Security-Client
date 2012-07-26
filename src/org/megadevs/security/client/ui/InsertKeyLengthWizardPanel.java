package org.megadevs.security.client.ui;

import java.awt.Component;
import java.awt.Dimension;

import javax.swing.Box;
import javax.swing.BoxLayout;
import javax.swing.JComboBox;
import javax.swing.JLabel;
import javax.swing.JPanel;

import org.megadevs.security.client.ui.wizard.WizardPanelDescriptor;

public class InsertKeyLengthWizardPanel extends WizardPanelDescriptor {

	public static String IDENTIFIER = "insert_key_length";
	
	private JComboBox box;
	private String[] items = new String[] {"1024", "1536", "2048"};
	
	public InsertKeyLengthWizardPanel() {
		setPanelComponent(createPanel());
		setPanelDescriptorIdentifier(IDENTIFIER);
	}

	private Component createPanel() {
		JPanel panel = new JPanel();
		panel.setLayout(new BoxLayout(panel, BoxLayout.Y_AXIS));
		
		JLabel label = new JLabel("Please choose the length of your first security key");
		box = new JComboBox(items);
		
		panel.add(label);
		panel.add(Box.createRigidArea(new Dimension(0, 10)));
		panel.add(box);
		panel.add(Box.createRigidArea(new Dimension(0, 125)));
		
		return panel;
	}

	public String getKeyLength() {
		return (String) box.getSelectedItem();
	}
	
	@Override
	public Object getBackPanelDescriptor() {
		return InsertInfromationsWizardPanel.IDENTIFIER;
	}
	
	@Override
	public Object getNextPanelDescriptor() {
		return FINISH;
	}
}
