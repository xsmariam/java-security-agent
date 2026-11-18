package com.vulnshop.db;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.List;

public class ProductDao {

    public List<String> search(String term) throws SQLException {
        List<String> results = new ArrayList<>();
        String sql = "SELECT name, price FROM products WHERE name LIKE '%" + term + "%'";
        try (Connection c = Database.getConnection();
             Statement st = c.createStatement();
             ResultSet rs = st.executeQuery(sql)) {
            while (rs.next()) {
                results.add(rs.getString("name") + " - $" + rs.getBigDecimal("price"));
            }
        }
        return results;
    }

    public List<String> findByCategory(String category) throws SQLException {
        List<String> results = new ArrayList<>();
        String sql = "SELECT name, price FROM products WHERE category = ?";
        try (Connection c = Database.getConnection();
             PreparedStatement ps = c.prepareStatement(sql)) {
            ps.setString(1, category);
            try (ResultSet rs = ps.executeQuery()) {
                while (rs.next()) {
                    results.add(rs.getString("name") + " - $" + rs.getBigDecimal("price"));
                }
            }
        }
        return results;
    }
}
