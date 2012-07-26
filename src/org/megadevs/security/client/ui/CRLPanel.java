package org.megadevs.security.client.ui;

import java.awt.BorderLayout;
import java.util.Collection;
import java.util.Iterator;
import java.util.Vector;

import javax.swing.BorderFactory;
import javax.swing.JScrollPane;
import javax.swing.JTable;
import javax.swing.ListSelectionModel;
import javax.swing.table.DefaultTableModel;

import org.bouncycastle.cert.X509CRLEntryHolder;
import org.bouncycastle.cert.X509CRLHolder;

@SuppressWarnings("serial")
public class CRLPanel extends CustomJPanelAdapter {

	private UI mUI;
	
	private JTable crlTable;
	private DefaultTableModel crlTableModel;
	
	public CRLPanel(UI ui) {
		mUI = ui;
		
		setLayout(new BorderLayout());

		crlTableModel = new DefaultTableModel();
		
		updateData();
		
		crlTable = new CustomJTableAdapter(crlTableModel);
		crlTable.setFillsViewportHeight(true);
		crlTable.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
		crlTable.setColumnSelectionAllowed(false);
		crlTable.setRowSelectionAllowed(false);
		
		JScrollPane crlPane = new JScrollPane(crlTable, JScrollPane.VERTICAL_SCROLLBAR_AS_NEEDED, JScrollPane.HORIZONTAL_SCROLLBAR_NEVER);
		crlPane.setBorder(BorderFactory.createTitledBorder("Certificates Revocation List"));
		
		add(crlPane, BorderLayout.CENTER);
	}
	
	@SuppressWarnings("unchecked")
	public void updateTablesData() {
		Vector<String> columnNames = new Vector<String>();
		columnNames.add("ID");
		columnNames.add("Date");
		
		Vector<Vector<String>> tableContent = new Vector<Vector<String>>();
		
		X509CRLHolder crl = mUI.getClient().getCRLFromDatabase();
		Collection<X509CRLEntryHolder> revokedCertificates = crl.getRevokedCertificates();
		Iterator<X509CRLEntryHolder> crlIterator = revokedCertificates.iterator();
		
		while (crlIterator.hasNext()) {
			X509CRLEntryHolder next = (X509CRLEntryHolder) crlIterator.next();
			Vector<String> row = new Vector<String>();
			
			row.add(next.getSerialNumber().toString());
			row.add(next.getRevocationDate().toString());
			
			tableContent.add(row);
		}

		crlTableModel.setDataVector(tableContent, columnNames);
		crlTableModel.fireTableDataChanged();

	}

	@Override
	public void updateData() {
		updateTablesData();
	}
}
