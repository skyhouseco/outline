"use strict";

/**
 * Tables for the mcp-hub plugin: a log of MCP tool calls, read by the SkyHouse
 * MCP hub as daily usage, and the people the hub has blocked from the MCP.
 * Rows are keyed on the email, so they outlive the user record.
 *
 * @type {import('sequelize-cli').Migration}
 */
module.exports = {
  async up(queryInterface, Sequelize) {
    await queryInterface.sequelize.transaction(async (transaction) => {
      await queryInterface.createTable(
        "mcp_tool_calls",
        {
          id: {
            type: Sequelize.BIGINT,
            autoIncrement: true,
            primaryKey: true,
          },
          userId: {
            type: Sequelize.UUID,
            allowNull: true,
          },
          email: {
            type: Sequelize.STRING,
            allowNull: false,
          },
          tool: {
            type: Sequelize.STRING,
            allowNull: false,
          },
          via: {
            type: Sequelize.STRING,
            allowNull: false,
          },
          ok: {
            type: Sequelize.BOOLEAN,
            allowNull: false,
          },
          durationMs: {
            type: Sequelize.INTEGER,
            allowNull: false,
          },
          createdAt: {
            type: Sequelize.DATE,
            allowNull: false,
          },
        },
        { transaction }
      );
      await queryInterface.addIndex("mcp_tool_calls", ["createdAt"], {
        transaction,
      });
      await queryInterface.addIndex("mcp_tool_calls", ["via", "email"], {
        transaction,
      });

      await queryInterface.createTable(
        "mcp_blocked_emails",
        {
          email: {
            type: Sequelize.STRING,
            primaryKey: true,
          },
          blockedBy: {
            type: Sequelize.STRING,
            allowNull: true,
          },
          createdAt: {
            type: Sequelize.DATE,
            allowNull: false,
          },
        },
        { transaction }
      );
    });
  },

  async down(queryInterface) {
    await queryInterface.sequelize.transaction(async (transaction) => {
      await queryInterface.dropTable("mcp_blocked_emails", { transaction });
      await queryInterface.dropTable("mcp_tool_calls", { transaction });
    });
  },
};
