package org.megadevs.security.client.ui;

import java.awt.Dimension;

import javax.swing.JTable;
import javax.swing.table.TableModel;

@SuppressWarnings("serial")
public class CustomJTableAdapter extends JTable {
	public CustomJTableAdapter(TableModel model) {
		super(model);
	}
	
	@Override
	public boolean isCellEditable(int row, int column) {
		return false;
	}
	
	@Override
	public Dimension getPreferredScrollableViewportSize() {
		return super.getPreferredSize();
	}
	
	public void setCustomScrollableViewportSize() {
		super.setPreferredScrollableViewportSize(super.getPreferredScrollableViewportSize());
	}
}
