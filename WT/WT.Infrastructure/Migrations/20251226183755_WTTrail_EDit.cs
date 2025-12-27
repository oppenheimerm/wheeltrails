using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace WT.Infrastructure.Migrations
{
    /// <inheritdoc />
    public partial class WTTrail_EDit : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.RenameColumn(
                name: "Longitude",
                table: "Trails",
                newName: "StartLng");

            migrationBuilder.RenameColumn(
                name: "Latitude",
                table: "Trails",
                newName: "StartLat");

            migrationBuilder.AddColumn<string>(
                name: "ElevationProfile",
                table: "Trails",
                type: "nvarchar(max)",
                nullable: false,
                defaultValue: "[]");

            migrationBuilder.AddColumn<double>(
                name: "EndLat",
                table: "Trails",
                type: "float",
                nullable: false,
                defaultValue: 0.0);

            migrationBuilder.AddColumn<double>(
                name: "EndLng",
                table: "Trails",
                type: "float",
                nullable: false,
                defaultValue: 0.0);

            migrationBuilder.AddColumn<double>(
                name: "LengthMeters",
                table: "Trails",
                type: "float",
                nullable: false,
                defaultValue: 0.0);

            migrationBuilder.CreateTable(
                name: "TrailPointsOfInterest",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    PoiLat = table.Column<double>(type: "float", nullable: false),
                    PoiLng = table.Column<double>(type: "float", nullable: false),
                    Type = table.Column<string>(type: "nvarchar(100)", maxLength: 100, nullable: false),
                    Notes = table.Column<string>(type: "nvarchar(300)", maxLength: 300, nullable: false),
                    CreatedAt = table.Column<DateTime>(type: "datetime2", nullable: false),
                    TrailId = table.Column<Guid>(type: "uniqueidentifier", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_TrailPointsOfInterest", x => x.Id);
                    table.ForeignKey(
                        name: "FK_TrailPointsOfInterest_Trails_TrailId",
                        column: x => x.TrailId,
                        principalTable: "Trails",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "TrailWaypoints",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    WaypointLat = table.Column<double>(type: "float", nullable: false),
                    WaypointLng = table.Column<double>(type: "float", nullable: false),
                    TrailId = table.Column<Guid>(type: "uniqueidentifier", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_TrailWaypoints", x => x.Id);
                    table.ForeignKey(
                        name: "FK_TrailWaypoints_Trails_TrailId",
                        column: x => x.TrailId,
                        principalTable: "Trails",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateIndex(
                name: "IX_TrailPointsOfInterest_TrailId",
                table: "TrailPointsOfInterest",
                column: "TrailId");

            migrationBuilder.CreateIndex(
                name: "IX_TrailWaypoints_TrailId",
                table: "TrailWaypoints",
                column: "TrailId");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "TrailPointsOfInterest");

            migrationBuilder.DropTable(
                name: "TrailWaypoints");

            migrationBuilder.DropColumn(
                name: "ElevationProfile",
                table: "Trails");

            migrationBuilder.DropColumn(
                name: "EndLat",
                table: "Trails");

            migrationBuilder.DropColumn(
                name: "EndLng",
                table: "Trails");

            migrationBuilder.DropColumn(
                name: "LengthMeters",
                table: "Trails");

            migrationBuilder.RenameColumn(
                name: "StartLng",
                table: "Trails",
                newName: "Longitude");

            migrationBuilder.RenameColumn(
                name: "StartLat",
                table: "Trails",
                newName: "Latitude");
        }
    }
}
