// SPDX-FileCopyrightText: 2025-2026 Marcus Grando
// SPDX-License-Identifier: LicenseRef-FCL-1.0-ALv2

import Foundation
@testable import MacDNS
import XCTest

final class ListEditStateTests: XCTestCase {
    private let a = UUID()
    private let b = UUID()

    func testStartsIdle() {
        let edit = ListEditState()
        XCTAssertNil(edit.editingID)
        XCTAssertFalse(edit.isAddingNew)
        XCTAssertFalse(edit.isEditing)
    }

    func testBeginAddClearsRowEdit() {
        var edit = ListEditState()
        edit.beginEdit(a)
        edit.beginAdd()
        XCTAssertNil(edit.editingID)
        XCTAssertTrue(edit.isAddingNew)
        XCTAssertTrue(edit.isEditing)
    }

    func testBeginEditClearsAdd() {
        var edit = ListEditState()
        edit.beginAdd()
        edit.beginEdit(a)
        XCTAssertEqual(edit.editingID, a)
        XCTAssertFalse(edit.isAddingNew)
        XCTAssertTrue(edit.isEditing)
    }

    func testFinishClearsEverything() {
        var edit = ListEditState()
        edit.beginEdit(a)
        edit.finish()
        XCTAssertNil(edit.editingID)
        XCTAssertFalse(edit.isAddingNew)
        XCTAssertFalse(edit.isEditing)
    }

    func testSwitchingRowsKeepsOneEditor() {
        var edit = ListEditState()
        edit.beginEdit(a)
        edit.beginEdit(b)
        XCTAssertEqual(edit.editingID, b)
        XCTAssertFalse(edit.isAddingNew)
    }
}
