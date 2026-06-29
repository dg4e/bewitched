// UI rendering for `App` (textually included from app.rs, shares its scope).

impl eframe::App for App {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        self.poll_bg(ctx);

        // Keep frozen live-memory values pinned.
        if !self.frozen.is_empty() && self.process_target.is_some() {
            self.enforce_frozen();
            ctx.request_repaint_after(std::time::Duration::from_millis(50));
        }

        egui::TopBottomPanel::top("menu").show(ctx, |ui| self.menu_bar(ui));
        egui::TopBottomPanel::bottom("status").show(ctx, |ui| self.status_bar(ui));

        // Dialog windows.
        self.search_window(ctx);
        self.goto_window(ctx);
        self.checksum_window(ctx);
        self.stats_window(ctx);
        self.export_window(ctx);
        self.pattern_window(ctx);
        self.tools_window(ctx);
        self.transform_window(ctx);
        self.strings_window(ctx);
        self.scan_window(ctx);
        self.ptrscan_window(ctx);
        self.signatures_window(ctx);
        self.byteplot_window(ctx);
        self.diff_window(ctx);
        self.disasm_window(ctx);
        self.kstruct_window(ctx);
        self.template_window(ctx);
        self.script_window(ctx);
        self.process_window(ctx);
        self.notes_window(ctx);
        self.regions_window(ctx);
        self.about_window(ctx);
        self.progress_window(ctx);

        // Keyboard only when no text field is capturing it and no op running.
        if !ctx.wants_keyboard_input() && self.bg.is_none() {
            self.handle_keys(ctx);
        }

        // Side panel must be declared before the central panel.
        self.inspector_panel(ctx);

        egui::CentralPanel::default()
            .frame(egui::Frame::none().fill(theme::BG))
            .show(ctx, |ui| self.hexview_ui(ui));
    }
}

impl App {
    fn menu_bar(&mut self, ui: &mut egui::Ui) {
        egui::menu::bar(ui, |ui| {
            ui.menu_button("File", |ui| {
                if ui.button("New").clicked() {
                    self.new_doc();
                    ui.close_menu();
                }
                if ui.button("Open file…   Ctrl+O").clicked() {
                    self.open_dialog();
                    ui.close_menu();
                }
                ui.menu_button("Open disk / RAM", |ui| {
                    ui.label(egui::RichText::new("raw devices").color(theme::GREEN_DIM));
                    ui.separator();
                    for dev in raw_targets() {
                        if ui.button(&dev.0).clicked() {
                            self.open_path(PathBuf::from(&dev.1));
                            ui.close_menu();
                        }
                    }
                    ui.separator();
                    ui.label(
                        egui::RichText::new("opens a device/path raw;\nneeds privileges")
                            .small()
                            .color(theme::GREEN_DIM),
                    );
                });
                if ui
                    .button("Open process memory…  (root/admin for other PIDs)")
                    .clicked()
                {
                    self.process_ui.open = true;
                    ui.close_menu();
                }
                ui.separator();
                if ui.button("Save   Ctrl+S").clicked() {
                    self.save();
                    ui.close_menu();
                }
                if ui.button("Save as…").clicked() {
                    self.save_as();
                    ui.close_menu();
                }
                ui.separator();
                if ui.button("Print…   (opens hex dump in default viewer)").clicked() {
                    self.print();
                    ui.close_menu();
                }
                ui.separator();
                if ui.button("Create IPS patch…   (diff vs original)").clicked() {
                    self.create_ips();
                    ui.close_menu();
                }
                if ui.button("Apply IPS patch…").clicked() {
                    self.apply_ips();
                    ui.close_menu();
                }
                if ui.button("Create BPS patch…   (diff vs original)").clicked() {
                    self.create_bps();
                    ui.close_menu();
                }
                if ui.button("Apply BPS patch…").clicked() {
                    self.apply_bps();
                    ui.close_menu();
                }
                ui.separator();
                if ui.button("Save annotations (.ghx)").clicked() {
                    self.save_annotations();
                    ui.close_menu();
                }
                if ui.button("Load annotations…").clicked() {
                    self.load_annotations_dialog();
                    ui.close_menu();
                }
                ui.separator();
                if ui.button("Quit").clicked() {
                    ui.ctx().send_viewport_cmd(egui::ViewportCommand::Close);
                }
            });

            ui.menu_button("Edit", |ui| {
                if ui.add_enabled(self.doc.can_undo(), egui::Button::new("Undo   Ctrl+Z")).clicked() {
                    self.doc.undo();
                    self.scroll_to_cursor = true;
                    ui.close_menu();
                }
                if ui.add_enabled(self.doc.can_redo(), egui::Button::new("Redo   Ctrl+Y")).clicked() {
                    self.doc.redo();
                    self.scroll_to_cursor = true;
                    ui.close_menu();
                }
                ui.separator();
                if ui.button("Cut   Ctrl+X").clicked() {
                    self.cut(ui.ctx());
                    ui.close_menu();
                }
                if ui.button("Copy   Ctrl+C").clicked() {
                    self.copy(ui.ctx());
                    ui.close_menu();
                }
                if ui.button("Paste (insert)   Ctrl+V").clicked() {
                    self.paste(false);
                    ui.close_menu();
                }
                if ui.button("Paste (overwrite)").clicked() {
                    self.paste(true);
                    ui.close_menu();
                }
                if ui.button("Select all   Ctrl+A").clicked() {
                    self.sel_anchor = Some(0);
                    self.cursor = self.doc.len().saturating_sub(1);
                    ui.close_menu();
                }
                if self.process_target.is_some()
                    && ui
                        .add_enabled(
                            self.selection_range().is_some(),
                            egui::Button::new("Poke selection → process"),
                        )
                        .clicked()
                {
                    self.poke_selection_to_process();
                    ui.close_menu();
                }
                ui.separator();
                let mode_label = match self.mode {
                    EditMode::Overwrite => "Mode: OVERWRITE  (Ins)",
                    EditMode::Insert => "Mode: INSERT  (Ins)",
                };
                if ui.button(mode_label).clicked() {
                    self.toggle_mode();
                    ui.close_menu();
                }
            });

            ui.menu_button("View", |ui| {
                ui.label("Character set");
                for cs in Charset::ALL {
                    if ui.radio(self.charset == *cs, cs.name()).clicked() {
                        self.charset = *cs;
                    }
                }
                ui.separator();
                ui.label("Byte grouping");
                for g in [1usize, 2, 4, 8, 16] {
                    if ui.radio(self.group == g, format!("{g} byte(s)")).clicked() {
                        self.group = g;
                    }
                }
                ui.separator();
                ui.label("Columns (bytes/row)");
                for c in [8usize, 16, 24, 32] {
                    if ui.radio(self.bytes_per_row == c, format!("{c}")).clicked() {
                        self.bytes_per_row = c;
                    }
                }
                ui.separator();
                if ui.radio(self.view_mode == ViewMode::Both, "Hex + text").clicked() {
                    self.view_mode = ViewMode::Both;
                }
                if ui.radio(self.view_mode == ViewMode::HexOnly, "Hex only").clicked() {
                    self.view_mode = ViewMode::HexOnly;
                }
                if ui.radio(self.view_mode == ViewMode::TextOnly, "Text only").clicked() {
                    self.view_mode = ViewMode::TextOnly;
                }
                ui.separator();
                ui.checkbox(&mut self.inspector_open, "Data inspector panel");
                ui.separator();
                ui.label("Data-folds / regions");
                if ui.add_enabled(self.selection_range().is_some(), egui::Button::new("Fold selection")).clicked() {
                    self.fold_selection(true);
                    ui.close_menu();
                }
                if ui.add_enabled(self.selection_range().is_some(), egui::Button::new("Fold selection (inaccessible)")).clicked() {
                    self.fold_selection(false);
                    ui.close_menu();
                }
                if ui.add_enabled(!self.regions.is_empty(), egui::Button::new("Unfold all")).clicked() {
                    self.unfold_all();
                    ui.close_menu();
                }
                if ui.button("Regions…").clicked() {
                    self.regions_open = true;
                    ui.close_menu();
                }
                if ui.button("Notes / annotations…").clicked() {
                    self.notes_open = true;
                    ui.close_menu();
                }
            });

            ui.menu_button("Search", |ui| {
                if ui.button("Find / Replace…   Ctrl+F").clicked() {
                    self.search.open = true;
                    ui.close_menu();
                }
                if ui.button("Go to address…   Ctrl+G").clicked() {
                    self.goto.open = true;
                    ui.close_menu();
                }
            });

            ui.menu_button("Tools", |ui| {
                if ui.button("Checksums / digests…").clicked() {
                    self.checksum.open = true;
                    ui.close_menu();
                }
                if ui.button("Statistics / analysis…").clicked() {
                    self.stats.open = true;
                    ui.close_menu();
                }
                if ui.button("Export…").clicked() {
                    self.export.open = true;
                    ui.close_menu();
                }
                if ui.button("Insert byte pattern…").clicked() {
                    self.pattern.open = true;
                    ui.close_menu();
                }
                if ui.button("Transform selection…").clicked() {
                    self.transform.open = true;
                    ui.close_menu();
                }
                ui.menu_button("Compression", |ui| {
                    if ui.button("Decompress (auto-detect)").clicked() {
                        self.do_decompress();
                        ui.close_menu();
                    }
                    ui.separator();
                    if ui.button("Compress — zlib").clicked() {
                        self.do_compress(compress::Codec::Zlib);
                        ui.close_menu();
                    }
                    if ui.button("Compress — gzip").clicked() {
                        self.do_compress(compress::Codec::Gzip);
                        ui.close_menu();
                    }
                    if ui.button("Compress — raw deflate").clicked() {
                        self.do_compress(compress::Codec::Deflate);
                        ui.close_menu();
                    }
                });
                if ui.button("Extract strings…").clicked() {
                    self.strings.open = true;
                    ui.close_menu();
                }
                if ui.button("Value scanner (memory/save editing)…").clicked() {
                    self.scan.open = true;
                    ui.close_menu();
                }
                if ui.button("Pointer scan…").clicked() {
                    self.ptrscan.open = true;
                    ui.close_menu();
                }
                if ui.button("Find signatures (binwalk)…").clicked() {
                    self.signatures.open = true;
                    ui.close_menu();
                }
                if ui.button("Byte map (visualize)…").clicked() {
                    self.byteplot.open = true;
                    ui.close_menu();
                }
                if ui.button("Compare / diff (detailed)…").clicked() {
                    self.diff.open = true;
                    ui.close_menu();
                }
                if ui.button("Disassembly (x86/x64)…").clicked() {
                    self.disasm.open = true;
                    ui.close_menu();
                }
                if ui.button("Binary template (structure view)…").clicked() {
                    self.template.open = true;
                    ui.close_menu();
                }
                if ui.button("Struct parser (nested tree)…").clicked() {
                    self.kstruct.open = true;
                    ui.close_menu();
                }
                if ui.button("Script (Rhai)…").clicked() {
                    self.script.open = true;
                    ui.close_menu();
                }
                ui.separator();
                if ui.button("File tools (shred / split / concat / compare)…").clicked() {
                    self.tools.open = true;
                    ui.close_menu();
                }
            });

            ui.menu_button("Help", |ui| {
                if ui.button("About ganghex").clicked() {
                    self.about_open = true;
                    ui.close_menu();
                }
                if ui.button("Find updates…").clicked() {
                    self.status = "ganghex 0.1.0 — you are running the latest local build".into();
                    ui.close_menu();
                }
            });

            ui.separator();
            ui.label(egui::RichText::new("ganghex").color(theme::GREEN).strong());
        });
    }

    fn status_bar(&mut self, ui: &mut egui::Ui) {
        ui.horizontal(|ui| {
            // Keep the whole bar on one line: fixed items extend to their natural
            // width and never wrap; only the variable status message truncates.
            ui.style_mut().wrap_mode = Some(egui::TextWrapMode::Extend);
            let modi = if self.doc.is_modified() { "*" } else { " " };
            ui.label(
                egui::RichText::new(format!("{}{}", modi, self.doc.label()))
                    .color(theme::AMBER),
            );
            ui.separator();
            ui.label(format!("offset {:#X} ({})", self.cursor, self.cursor));
            ui.separator();
            if self.cursor < self.doc.len() {
                let b = self.byte_at(self.cursor);
                ui.label(format!("byte {:02X} = {:3} = {:#010b}", b, b, b));
            }
            if let Some((s, e)) = self.selection_range() {
                ui.separator();
                ui.label(
                    egui::RichText::new(format!("sel {:#X}..{:#X} ({} bytes)", s, e, e - s))
                        .color(theme::AMBER),
                );
            }
            ui.separator();
            ui.label(human(self.doc.len()));
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                let mode = match self.mode {
                    EditMode::Overwrite => "OVR",
                    EditMode::Insert => "INS",
                };
                ui.label(egui::RichText::new(mode).color(theme::GREEN).strong());
                ui.separator();
                if self.process_target.is_some() {
                    ui.label(
                        egui::RichText::new("⏺ LIVE")
                            .color(theme::RED)
                            .strong(),
                    )
                    .on_hover_text("editing writes through to process memory");
                    ui.separator();
                    if !self.frozen.is_empty() {
                        ui.label(
                            egui::RichText::new(format!("❄ {}", self.frozen.len()))
                                .color(theme::RED)
                                .strong(),
                        )
                        .on_hover_text("frozen values being re-poked");
                        ui.separator();
                    }
                }
                if !self.extra_cursors.is_empty() {
                    ui.label(
                        egui::RichText::new(format!("{} cursors", self.extra_cursors.len() + 1))
                            .color(theme::AMBER),
                    )
                    .on_hover_text("Ctrl/Cmd+click to add carets · Esc to clear");
                    ui.separator();
                }
                ui.add(
                    egui::Label::new(
                        egui::RichText::new(&self.status).color(theme::status_color(&self.status)),
                    )
                    .truncate(),
                );
            });
        });
    }

    fn toggle_mode(&mut self) {
        self.mode = match self.mode {
            EditMode::Overwrite => EditMode::Insert,
            EditMode::Insert => EditMode::Overwrite,
        };
    }

    // ---- the hex view ----

    fn hexview_ui(&mut self, ui: &mut egui::Ui) {
        let font = theme::mono(13.0);
        let char_w = ui.fonts(|f| f.glyph_width(&font, '0')).max(1.0);
        let row_h = ui.fonts(|f| f.row_height(&font));
        ui.spacing_mut().item_spacing = egui::vec2(0.0, 0.0);

        let len = self.doc.len();
        let bpr = self.bytes_per_row as u64;
        let layout = Layout::new(self.bytes_per_row, self.group, len, self.view_mode);
        let vm = self.view_map();
        let total_rows = vm.total_rows().max(1);

        self.page_rows = ((ui.available_height() / row_h) as usize).max(1);
        let scroll_to = self.scroll_to_cursor;
        self.scroll_to_cursor = false;
        let cursor_row = vm.offset_to_row(self.cursor).unwrap_or(0);

        egui::ScrollArea::both()
            .auto_shrink([false, false])
            .show_rows(ui, row_h, total_rows, |ui, range| {
                for r in range {
                    match vm.row(r).unwrap_or(RowItem::Data { base: r as u64 * bpr }) {
                        RowItem::Fold { region } => {
                            let reg = &self.regions[region];
                            let mark = if reg.accessible { "▸" } else { "⊘" };
                            let txt = format!(
                                "  {} {}   {:#X}..{:#X}   ({} bytes folded — click to expand)",
                                mark,
                                reg.label,
                                reg.start,
                                reg.end(),
                                reg.len
                            );
                            let resp = ui.add(
                                egui::Label::new(
                                    egui::RichText::new(txt)
                                        .color(theme::AMBER)
                                        .background_color(theme::BG_ALT),
                                )
                                .sense(Sense::click())
                                .selectable(false),
                            );
                            if resp.clicked() {
                                self.regions[region].folded = false;
                                self.scroll_to_cursor = true;
                            }
                        }
                        RowItem::Data { base } => {
                            let resp = self.render_data_row(ui, base, &font, &layout, len);
                            if scroll_to && r == cursor_row {
                                resp.scroll_to_me(Some(egui::Align::Center));
                            }
                            if (resp.clicked() || resp.dragged()) && self.bg.is_none() {
                                if let Some(pos) = resp.interact_pointer_pos() {
                                    let relx = pos.x - resp.rect.left();
                                    let col = (relx / char_w).floor();
                                    if col >= 0.0 {
                                        if let Some((i, pane, nib)) =
                                            layout.col_to_byte(col as usize)
                                        {
                                            let off = (base + i as u64).min(len);
                                            let ctrl = ui.input(|inp| inp.modifiers.command);
                                            if ctrl && resp.clicked() {
                                                self.toggle_extra_cursor(off);
                                            } else {
                                                let extend = resp.dragged();
                                                self.click_to(off, pane, nib, extend);
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            });
    }

    /// Render one data row and return its response (for click/scroll handling).
    fn render_data_row(
        &self,
        ui: &mut egui::Ui,
        base: u64,
        font: &egui::FontId,
        layout: &Layout,
        len: u64,
    ) -> egui::Response {
        let raw = self.doc.read_range(base, self.bytes_per_row);
        let bytes: Vec<Option<u8>> =
            (0..self.bytes_per_row).map(|i| raw.get(i).copied()).collect();
        let modified: Vec<bool> = (0..self.bytes_per_row)
            .map(|i| {
                let off = base + i as u64;
                off < len && self.doc.is_byte_modified(off)
            })
            .collect();
        let sel = self.selection_range();
        let selected: Vec<bool> = (0..self.bytes_per_row)
            .map(|i| {
                let off = base + i as u64;
                sel.map(|(s, e)| off >= s && off < e).unwrap_or(false)
            })
            .collect();
        let cursor = if self.cursor >= base && self.cursor < base + self.bytes_per_row as u64 {
            Some(((self.cursor - base) as usize, self.nibble, self.pane))
        } else {
            None
        };
        let extra: Vec<bool> = (0..self.bytes_per_row)
            .map(|i| {
                let off = base + i as u64;
                self.extra_cursors.contains(&off)
            })
            .collect();
        let ctx = hexview::RowCtx {
            bytes: &bytes,
            modified: &modified,
            selected: &selected,
            extra: &extra,
            base_addr: base,
            charset: self.charset,
            cursor,
            editing_pane: self.pane,
            font: font.clone(),
        };
        let job = hexview::build_row(layout, &ctx);
        ui.add(
            egui::Label::new(job)
                .sense(Sense::click_and_drag())
                .selectable(false),
        )
    }

    fn click_to(&mut self, off: u64, pane: Pane, nib: u8, extend: bool) {
        if extend {
            if self.sel_anchor.is_none() {
                self.sel_anchor = Some(self.cursor);
            }
        } else {
            self.sel_anchor = None;
        }
        self.cursor = off;
        self.pane = pane;
        self.nibble = nib;
    }

    // ---- keyboard ----

    fn handle_keys(&mut self, ctx: &egui::Context) {
        let events = ctx.input(|i| i.events.clone());
        for ev in events {
            match ev {
                egui::Event::Key {
                    key,
                    pressed: true,
                    modifiers,
                    ..
                } => self.on_key(key, modifiers, ctx),
                egui::Event::Text(t) => self.on_text(&t),
                egui::Event::Paste(s) => {
                    // Treat pasted text as hex if it looks like hex, else raw bytes.
                    if let Ok(b) = pattern::parse_hex_pattern(&s) {
                        self.clipboard = b;
                    } else {
                        self.clipboard = s.into_bytes();
                    }
                    self.paste(self.mode == EditMode::Overwrite);
                }
                _ => {}
            }
        }
    }

    fn on_text(&mut self, t: &str) {
        for ch in t.chars() {
            match self.pane {
                Pane::Hex => {
                    if let Some(d) = ch.to_digit(16) {
                        self.input_hex_nibble(d as u8);
                    }
                }
                Pane::Text => {
                    if !ch.is_control() && (ch as u32) < 0x100 {
                        self.input_byte(ch as u8);
                    }
                }
            }
        }
    }

    fn on_key(&mut self, key: Key, m: egui::Modifiers, ctx: &egui::Context) {
        let bpr = self.bytes_per_row as i64;
        let cmd = m.command;
        let shift = m.shift;

        // Bookmarks: Ctrl+Shift+N set, Ctrl+N go.
        if cmd {
            if let Some(n) = digit_of(key) {
                if shift {
                    self.bookmarks[n] = Some(self.cursor);
                    self.status = format!("bookmark {n} set at {:#X}", self.cursor);
                } else if let Some(addr) = self.bookmarks[n] {
                    self.set_cursor(addr, false);
                    self.status = format!("jumped to bookmark {n}");
                }
                return;
            }
        }

        if cmd {
            match key {
                Key::O => self.open_dialog(),
                Key::S => self.save(),
                Key::Z => {
                    self.doc.undo();
                    self.scroll_to_cursor = true;
                }
                Key::Y => {
                    self.doc.redo();
                    self.scroll_to_cursor = true;
                }
                Key::C => self.copy(ctx),
                Key::X => self.cut(ctx),
                Key::V => self.paste(self.mode == EditMode::Overwrite),
                Key::F => self.search.open = true,
                Key::G => self.goto.open = true,
                Key::A => {
                    self.sel_anchor = Some(0);
                    self.cursor = self.doc.len().saturating_sub(1);
                }
                Key::ArrowLeft => self.nibble_move(-1),
                Key::ArrowRight => self.nibble_move(1),
                _ => {}
            }
            return;
        }

        match key {
            Key::ArrowLeft => self.move_by(-1, shift),
            Key::ArrowRight => self.move_by(1, shift),
            Key::ArrowUp => self.move_by(-bpr, shift),
            Key::ArrowDown => self.move_by(bpr, shift),
            Key::PageUp => self.move_by(-(bpr * self.page_rows as i64), shift),
            Key::PageDown => self.move_by(bpr * self.page_rows as i64, shift),
            Key::Home => {
                let row_start = self.cursor - (self.cursor % bpr as u64);
                self.set_cursor(row_start, shift);
            }
            Key::End => {
                let row_end = (self.cursor - self.cursor % bpr as u64) + bpr as u64 - 1;
                self.set_cursor(row_end.min(self.doc.len()), shift);
            }
            Key::Tab => {
                self.pane = match self.pane {
                    Pane::Hex => Pane::Text,
                    Pane::Text => Pane::Hex,
                };
                self.nibble = 0;
            }
            Key::Insert => self.toggle_mode(),
            Key::Backspace => self.backspace(),
            Key::Delete => self.delete_forward(),
            Key::Escape => {
                self.clear_selection();
                if !self.extra_cursors.is_empty() {
                    self.extra_cursors.clear();
                    self.status = "cleared extra cursors".into();
                }
            }
            _ => {}
        }
    }

    fn nibble_move(&mut self, dir: i64) {
        if dir > 0 {
            if self.nibble == 0 {
                self.nibble = 1;
            } else {
                self.nibble = 0;
                self.cursor = (self.cursor + 1).min(self.doc.len());
            }
        } else if self.nibble == 1 {
            self.nibble = 0;
        } else if self.cursor > 0 {
            self.cursor -= 1;
            self.nibble = 1;
        }
        self.scroll_to_cursor = true;
    }

    // ---- dialogs ----

    fn search_window(&mut self, ctx: &egui::Context) {
        let mut open = self.search.open;
        egui::Window::new("Find / Replace")
            .open(&mut open)
            .resizable(false)
            .show(ctx, |ui| {
                egui::ComboBox::from_label("Data type")
                    .selected_text(TYPES[self.search.data_type].0)
                    .show_ui(ui, |ui| {
                        for (i, t) in TYPES.iter().enumerate() {
                            ui.selectable_value(&mut self.search.data_type, i, t.0);
                        }
                    });
                ui.horizontal(|ui| {
                    ui.label("Find:   ");
                    ui.text_edit_singleline(&mut self.search.needle);
                });
                if TYPES[self.search.data_type].1 == search::DataType::Hex {
                    ui.label(
                        egui::RichText::new("hex supports '?' wildcards, e.g. DE ?? BE EF")
                            .small()
                            .color(theme::GREEN_DIM),
                    );
                }
                ui.horizontal(|ui| {
                    ui.label("Replace:");
                    ui.text_edit_singleline(&mut self.search.replace);
                });
                ui.horizontal(|ui| {
                    ui.checkbox(&mut self.search.case_insensitive, "Ignore case");
                    ui.checkbox(&mut self.search.big_endian, "Big-endian");
                });
                ui.separator();
                ui.horizontal(|ui| {
                    if ui.button("◀ Find prev").clicked() {
                        self.do_find(search::Direction::Backward);
                    }
                    if ui.button("Find next ▶").clicked() {
                        self.do_find(search::Direction::Forward);
                    }
                    if ui.button("Find first").clicked() {
                        self.do_find(search::Direction::All);
                    }
                });
                ui.horizontal(|ui| {
                    if ui.button("Replace & find").clicked() {
                        self.do_replace_one();
                    }
                    if ui.button("Replace all").clicked() {
                        self.do_replace_all();
                    }
                });
                if !self.search.status.is_empty() {
                    ui.separator();
                    ui.label(egui::RichText::new(&self.search.status).color(theme::AMBER));
                }
            });
        self.search.open = open;
    }

    fn needle_bytes(&self, which: &str) -> Result<Vec<u8>, String> {
        let endian = if self.search.big_endian {
            search::Endian::Big
        } else {
            search::Endian::Little
        };
        let s = if which == "find" {
            &self.search.needle
        } else {
            &self.search.replace
        };
        search::needle_bytes(s, TYPES[self.search.data_type].1, endian, self.search.case_insensitive)
    }

    fn do_find(&mut self, dir: search::Direction) {
        // Wildcard "AOB" search: a hex pattern containing '?' uses masked search.
        let is_hex = TYPES[self.search.data_type].1 == search::DataType::Hex;
        if is_hex && self.search.needle.contains('?') {
            return self.do_find_masked(dir);
        }
        let needle = match self.needle_bytes("find") {
            Ok(n) if !n.is_empty() => n,
            Ok(_) => {
                self.search.status = "empty search".into();
                return;
            }
            Err(e) => {
                self.search.status = e;
                return;
            }
        };
        let from = match dir {
            search::Direction::Forward => self.cursor + 1,
            search::Direction::Backward => self.cursor,
            search::Direction::All => 0,
        };
        match search::find(&self.doc, &needle, from, dir, self.search.case_insensitive) {
            Some(off) => {
                self.cursor = off;
                self.nibble = 0;
                self.sel_anchor = Some(off);
                self.cursor = off + needle.len() as u64 - 1;
                self.scroll_to_cursor = true;
                self.search.status = format!("match at {:#X}", off);
            }
            None => self.search.status = "not found".into(),
        }
    }

    fn do_find_masked(&mut self, dir: search::Direction) {
        let (pat, mask) = match search::parse_hex_mask(&self.search.needle) {
            Ok(pm) => pm,
            Err(e) => {
                self.search.status = e;
                return;
            }
        };
        let from = match dir {
            search::Direction::Backward => 0, // masked search is forward-only
            search::Direction::Forward => self.cursor + 1,
            search::Direction::All => 0,
        };
        match search::find_masked(&self.doc, &pat, &mask, from) {
            Some(off) => {
                self.sel_anchor = Some(off);
                self.cursor = off + pat.len() as u64 - 1;
                self.nibble = 0;
                self.scroll_to_cursor = true;
                self.search.status = format!("pattern match at {:#X}", off);
            }
            None => self.search.status = "pattern not found".into(),
        }
    }

    fn do_replace_one(&mut self) {
        let (needle, repl) = match (self.needle_bytes("find"), self.needle_bytes("repl")) {
            (Ok(n), Ok(r)) if !n.is_empty() => (n, r),
            (Err(e), _) | (_, Err(e)) => {
                self.search.status = e;
                return;
            }
            _ => {
                self.search.status = "empty search".into();
                return;
            }
        };
        if let Some((s, _)) = self.selection_range() {
            let cur = self.doc.read_range(s, needle.len());
            let eq = if self.search.case_insensitive {
                cur.eq_ignore_ascii_case(&needle)
            } else {
                cur == needle
            };
            if eq {
                self.doc.replace(s, needle.len() as u64, &repl);
                self.cursor = s + repl.len() as u64;
                self.sel_anchor = None;
            }
        }
        self.do_find(search::Direction::Forward);
    }

    fn do_replace_all(&mut self) {
        let (needle, repl) = match (self.needle_bytes("find"), self.needle_bytes("repl")) {
            (Ok(n), Ok(r)) if !n.is_empty() => (n, r),
            (Err(e), _) | (_, Err(e)) => {
                self.search.status = e;
                return;
            }
            _ => {
                self.search.status = "empty search".into();
                return;
            }
        };
        let p = Progress::default();
        let n = search::replace_all(&mut self.doc, &needle, &repl, self.search.case_insensitive, &p);
        self.search.status = format!("replaced {n} occurrence(s)");
        self.scroll_to_cursor = true;
    }

    fn goto_window(&mut self, ctx: &egui::Context) {
        let mut open = self.goto.open;
        egui::Window::new("Go to address")
            .open(&mut open)
            .resizable(false)
            .show(ctx, |ui| {
                ui.label("Address (0x.. hex, or decimal):");
                let resp = ui.text_edit_singleline(&mut self.goto.text);
                let go = ui.button("Go").clicked()
                    || (resp.lost_focus() && ui.input(|i| i.key_pressed(Key::Enter)));
                if go {
                    match parse_addr(&self.goto.text) {
                        Some(a) => {
                            self.set_cursor(a.min(self.doc.len()), false);
                            self.goto.status = format!("at {:#X}", a);
                        }
                        None => self.goto.status = "invalid address".into(),
                    }
                }
                if !self.goto.status.is_empty() {
                    ui.label(egui::RichText::new(&self.goto.status).color(theme::AMBER));
                }
            });
        self.goto.open = open;
    }

    fn checksum_window(&mut self, ctx: &egui::Context) {
        let mut open = self.checksum.open;
        egui::Window::new("Checksums / digests")
            .open(&mut open)
            .resizable(true)
            .show(ctx, |ui| {
                ui.checkbox(&mut self.checksum.whole_file, "Whole file (else selection)");
                ui.separator();
                egui::Grid::new("algos").num_columns(2).show(ui, |ui| {
                    for (i, a) in checksum::Algo::ALL.iter().enumerate() {
                        ui.checkbox(&mut self.checksum.selected[i], a.name());
                        if i % 2 == 1 {
                            ui.end_row();
                        }
                    }
                });
                ui.separator();
                if ui.button("Compute").clicked() {
                    let algos: Vec<checksum::Algo> = checksum::Algo::ALL
                        .iter()
                        .enumerate()
                        .filter(|(i, _)| self.checksum.selected[*i])
                        .map(|(_, a)| *a)
                        .collect();
                    let (off, len) = self.scope(self.checksum.whole_file);
                    let reader = self.doc.reader();
                    self.start_bg("computing digests", len, move |p| {
                        BgOutcome::Checksum(checksum::compute(&reader, off, len, &algos, &p))
                    });
                }
                ui.separator();
                let mut write: Option<String> = None;
                egui::Grid::new("results").num_columns(2).striped(true).show(ui, |ui| {
                    for (a, v) in &self.checksum.results {
                        ui.label(egui::RichText::new(a.name()).color(theme::ADDR));
                        ui.horizontal(|ui| {
                            ui.label(egui::RichText::new(v).color(theme::GREEN).monospace());
                            if ui.small_button("copy").clicked() {
                                ui.ctx().copy_text(v.clone());
                            }
                            if ui
                                .small_button("write@cursor")
                                .on_hover_text("overwrite bytes at the cursor with this digest (checksum repair)")
                                .clicked()
                            {
                                write = Some(v.clone());
                            }
                        });
                        ui.end_row();
                    }
                });
                if let Some(hex) = write {
                    self.write_hex_at_cursor(&hex);
                }
                ui.separator();
                ui.collapsing("Custom CRC", |ui| {
                    ui.label(
                        egui::RichText::new("Rocksoft model — poly/init/xorout in hex")
                            .small()
                            .color(theme::GREEN_DIM),
                    );
                    egui::Grid::new("ccrc").num_columns(2).show(ui, |ui| {
                        ui.label("Width (bits)");
                        ui.add(egui::TextEdit::singleline(&mut self.checksum.crc_width).desired_width(80.0));
                        ui.end_row();
                        ui.label("Poly");
                        ui.add(egui::TextEdit::singleline(&mut self.checksum.crc_poly).desired_width(160.0));
                        ui.end_row();
                        ui.label("Init");
                        ui.add(egui::TextEdit::singleline(&mut self.checksum.crc_init).desired_width(160.0));
                        ui.end_row();
                        ui.label("XorOut");
                        ui.add(egui::TextEdit::singleline(&mut self.checksum.crc_xorout).desired_width(160.0));
                        ui.end_row();
                    });
                    ui.horizontal(|ui| {
                        ui.checkbox(&mut self.checksum.crc_refin, "RefIn");
                        ui.checkbox(&mut self.checksum.crc_refout, "RefOut");
                    });
                    if ui.button("Compute CRC").clicked() {
                        self.compute_custom_crc();
                    }
                    if !self.checksum.crc_result.is_empty() {
                        ui.horizontal(|ui| {
                            ui.label(egui::RichText::new(&self.checksum.crc_result).color(theme::GREEN).monospace());
                            if ui.small_button("copy").clicked() {
                                ui.ctx().copy_text(self.checksum.crc_result.clone());
                            }
                        });
                    }
                });
            });
        self.checksum.open = open;
    }

    fn stats_window(&mut self, ctx: &egui::Context) {
        let mut open = self.stats.open;
        egui::Window::new("Statistics / analysis")
            .open(&mut open)
            .resizable(true)
            .default_width(560.0)
            .show(ctx, |ui| {
                ui.checkbox(&mut self.stats.whole_file, "Whole file (else selection)");
                ui.horizontal(|ui| {
                    if ui.button("Analyze").clicked() {
                        let (off, len) = self.scope(self.stats.whole_file);
                        let reader = self.doc.reader();
                        self.start_bg("analyzing", len, move |p| {
                            BgOutcome::Stats(Box::new(stats::analyze(&reader, off, len, &p)))
                        });
                    }
                    if ui.button("Entropy map").clicked() {
                        self.do_entropy_map();
                    }
                });
                if !self.stats.emap.is_empty() {
                    ui.separator();
                    ui.label(
                        egui::RichText::new("entropy map (file start → end; click to jump)")
                            .color(theme::GREEN_DIM),
                    );
                    let (off, len) = self.scope(self.stats.whole_file);
                    if let Some(frac) = draw_entropy_map(ui, &self.stats.emap) {
                        let target = off + (frac as f64 * len as f64) as u64;
                        self.set_cursor(target.min(self.doc.len()), false);
                    }
                }
                ui.separator();
                if let Some(s) = &self.stats.result {
                    ui.label(format!("Total bytes : {}", s.total));
                    ui.label(format!("Entropy     : {:.4} bits/byte (max 8)", s.entropy));
                    ui.label(format!("Looks like  : {}", s.classify()));
                    if let Some((b, c)) = s.most_common() {
                        ui.label(format!("Most common : {:02X} ({} times)", b, c));
                    }
                    ui.separator();
                    ui.label(egui::RichText::new("byte distribution (0x00 → 0xFF)").color(theme::GREEN_DIM));
                    draw_distribution(ui, &s.counts);
                } else {
                    ui.label(egui::RichText::new("run Analyze to see the distribution").color(theme::GREEN_DIM));
                }
            });
        self.stats.open = open;
    }

    fn export_window(&mut self, ctx: &egui::Context) {
        let mut open = self.export.open;
        egui::Window::new("Export")
            .open(&mut open)
            .resizable(true)
            .default_width(560.0)
            .show(ctx, |ui| {
                egui::ComboBox::from_label("Format")
                    .selected_text(export::Format::ALL[self.export.fmt].name())
                    .show_ui(ui, |ui| {
                        for (i, f) in export::Format::ALL.iter().enumerate() {
                            ui.selectable_value(&mut self.export.fmt, i, f.name());
                        }
                    });
                ui.checkbox(&mut self.export.whole_file, "Whole file (else selection)");
                ui.horizontal(|ui| {
                    if ui.button("Preview").clicked() {
                        self.export.preview = self.gen_export();
                    }
                    if ui.button("Copy to clipboard").clicked() {
                        let s = self.gen_export();
                        ui.ctx().copy_text(s.clone());
                        self.export.preview = s;
                    }
                    if ui.button("Save to file…").clicked() {
                        let s = self.gen_export();
                        let ext = export::Format::ALL[self.export.fmt].extension();
                        if let Some(p) = rfd::FileDialog::new().add_filter("export", &[ext]).save_file() {
                            let _ = std::fs::write(&p, s.as_bytes());
                            self.status = format!("exported to {}", p.display());
                        }
                    }
                });
                ui.separator();
                egui::ScrollArea::vertical().max_height(320.0).show(ui, |ui| {
                    ui.add(
                        egui::TextEdit::multiline(&mut self.export.preview.as_str())
                            .font(egui::TextStyle::Monospace)
                            .desired_width(f32::INFINITY),
                    );
                });
            });
        self.export.open = open;
    }

    fn gen_export(&self) -> String {
        let (off, len) = self.scope(self.export.whole_file);
        export::export(&self.doc, off, len, export::Format::ALL[self.export.fmt])
    }

    fn pattern_window(&mut self, ctx: &egui::Context) {
        let mut open = self.pattern.open;
        egui::Window::new("Insert byte pattern")
            .open(&mut open)
            .resizable(false)
            .show(ctx, |ui| {
                ui.horizontal(|ui| {
                    ui.label("Pattern (hex):");
                    ui.text_edit_singleline(&mut self.pattern.hex);
                });
                ui.horizontal(|ui| {
                    ui.label("Length (bytes):");
                    ui.text_edit_singleline(&mut self.pattern.count);
                });
                ui.radio_value(&mut self.pattern.mode, 0, "Insert at cursor");
                ui.radio_value(&mut self.pattern.mode, 1, "Overwrite at cursor");
                ui.radio_value(&mut self.pattern.mode, 2, "Fill selection");
                ui.separator();
                if ui.button("Apply").clicked() {
                    self.apply_pattern();
                }
            });
        self.pattern.open = open;
    }

    fn apply_pattern(&mut self) {
        let pat = match pattern::parse_hex_pattern(&self.pattern.hex) {
            Ok(p) => p,
            Err(e) => {
                self.status = format!("pattern error: {e}");
                return;
            }
        };
        match self.pattern.mode {
            2 => {
                if let Some((s, e)) = self.selection_range() {
                    let data = pattern::build(&pat, e - s);
                    self.doc.overwrite(s, &data);
                    self.status = format!("filled {} bytes", e - s);
                } else {
                    self.status = "no selection to fill".into();
                }
            }
            mode => {
                let count: u64 = self.pattern.count.trim().parse().unwrap_or(0);
                let data = pattern::build(&pat, count);
                if mode == 0 {
                    self.doc.insert(self.cursor, &data);
                } else {
                    self.doc.overwrite(self.cursor, &data);
                }
                self.cursor += data.len() as u64;
                self.status = format!("wrote {} bytes", data.len());
            }
        }
        self.scroll_to_cursor = true;
    }

    fn tools_window(&mut self, ctx: &egui::Context) {
        let mut open = self.tools.open;
        egui::Window::new("File tools")
            .open(&mut open)
            .resizable(false)
            .default_width(420.0)
            .show(ctx, |ui| {
                ui.label(egui::RichText::new("Shredder — overwrite then delete").color(theme::GREEN));
                ui.horizontal(|ui| {
                    ui.label("Passes:");
                    ui.text_edit_singleline(&mut self.tools.shred_passes);
                    if ui.button("Pick & shred…").clicked() {
                        if let Some(p) = rfd::FileDialog::new().pick_file() {
                            let passes: u32 = self.tools.shred_passes.trim().parse().unwrap_or(3);
                            let total = std::fs::metadata(&p).map(|m| m.len()).unwrap_or(0);
                            self.start_bg("shredding", total * passes as u64, move |pr| {
                                match fileops::shred(&p, passes, &pr) {
                                    Ok(()) => BgOutcome::Message(format!("shredded {}", p.display())),
                                    Err(e) => BgOutcome::Message(format!("shred failed: {e}")),
                                }
                            });
                        }
                    }
                });
                ui.label(egui::RichText::new("note: on SSD/CoW filesystems overwrite may not hit original blocks").small().color(theme::GREEN_DIM));
                ui.separator();

                ui.label(egui::RichText::new("Split file into parts").color(theme::GREEN));
                ui.horizontal(|ui| {
                    ui.label("Chunk size (bytes):");
                    ui.text_edit_singleline(&mut self.tools.split_size);
                    if ui.button("Pick & split…").clicked() {
                        if let Some(p) = rfd::FileDialog::new().pick_file() {
                            let size: u64 = self.tools.split_size.trim().parse().unwrap_or(1 << 20);
                            let total = std::fs::metadata(&p).map(|m| m.len()).unwrap_or(0);
                            self.start_bg("splitting", total, move |pr| {
                                match fileops::split(&p, size.max(1), &pr) {
                                    Ok(parts) => BgOutcome::Message(format!("split into {} parts", parts.len())),
                                    Err(e) => BgOutcome::Message(format!("split failed: {e}")),
                                }
                            });
                        }
                    }
                });
                ui.separator();

                ui.label(egui::RichText::new("Concatenate files").color(theme::GREEN));
                ui.horizontal(|ui| {
                    if ui.button("Pick inputs…").clicked() {
                        if let Some(files) = rfd::FileDialog::new().pick_files() {
                            self.tools.concat_inputs = files;
                        }
                    }
                    ui.label(format!("{} file(s) selected", self.tools.concat_inputs.len()));
                });
                if ui.button("Concatenate to…").clicked() && !self.tools.concat_inputs.is_empty() {
                    if let Some(out) = rfd::FileDialog::new().save_file() {
                        let inputs = self.tools.concat_inputs.clone();
                        let total: u64 = inputs.iter().filter_map(|p| std::fs::metadata(p).ok()).map(|m| m.len()).sum();
                        self.start_bg("concatenating", total, move |pr| {
                            match fileops::concat(&inputs, &out, &pr) {
                                Ok(()) => BgOutcome::Message(format!("concatenated to {}", out.display())),
                                Err(e) => BgOutcome::Message(format!("concat failed: {e}")),
                            }
                        });
                    }
                }
                ui.separator();

                ui.label(egui::RichText::new("Compare two files").color(theme::GREEN));
                if ui.button("Pick A then B…").clicked() {
                    if let (Some(a), Some(b)) = (
                        rfd::FileDialog::new().set_title("Pick file A").pick_file(),
                        rfd::FileDialog::new().set_title("Pick file B").pick_file(),
                    ) {
                        self.start_bg("comparing", 0, move |pr| match fileops::compare(&a, &b, &pr) {
                            Ok(r) => {
                                if r.equal {
                                    BgOutcome::Message("files are identical".into())
                                } else if let Some(d) = r.first_diff {
                                    BgOutcome::Message(format!(
                                        "differ at {:#X}; sizes {} vs {}",
                                        d, r.len_a, r.len_b
                                    ))
                                } else {
                                    BgOutcome::Message("files differ".into())
                                }
                            }
                            Err(e) => BgOutcome::Message(format!("compare failed: {e}")),
                        });
                    }
                }
                if !self.tools.status.is_empty() {
                    ui.label(&self.tools.status);
                }
            });
        self.tools.open = open;
    }

    fn regions_window(&mut self, ctx: &egui::Context) {
        let mut open = self.regions_open;
        egui::Window::new("Regions / data-folds")
            .open(&mut open)
            .resizable(true)
            .default_width(560.0)
            .show(ctx, |ui| {
                ui.label(
                    egui::RichText::new(
                        "Regions mark sections of the document. Folded regions collapse to a \
                         single marker row; inaccessible regions (e.g. unreadable RAM) are \
                         hidden by default.",
                    )
                    .small()
                    .color(theme::GREEN_DIM),
                );
                ui.horizontal(|ui| {
                    if ui
                        .add_enabled(
                            self.selection_range().is_some(),
                            egui::Button::new("Fold selection"),
                        )
                        .clicked()
                    {
                        self.fold_selection(true);
                    }
                    if ui.button("Unfold all").clicked() {
                        self.unfold_all();
                    }
                    if ui.button("Clear all").clicked() {
                        self.regions.clear();
                    }
                });
                ui.separator();
                let mut remove: Option<usize> = None;
                egui::ScrollArea::vertical().max_height(300.0).show(ui, |ui| {
                    egui::Grid::new("regions_grid")
                        .num_columns(5)
                        .striped(true)
                        .show(ui, |ui| {
                            ui.label(egui::RichText::new("label").color(theme::ADDR));
                            ui.label(egui::RichText::new("range").color(theme::ADDR));
                            ui.label(egui::RichText::new("folded").color(theme::ADDR));
                            ui.label(egui::RichText::new("accessible").color(theme::ADDR));
                            ui.label("");
                            ui.end_row();
                            for (i, r) in self.regions.iter_mut().enumerate() {
                                ui.text_edit_singleline(&mut r.label);
                                ui.label(format!("{:#X}..{:#X} ({})", r.start, r.end(), r.len));
                                ui.checkbox(&mut r.folded, "");
                                ui.checkbox(&mut r.accessible, "");
                                if ui.small_button("✕").clicked() {
                                    remove = Some(i);
                                }
                                ui.end_row();
                            }
                        });
                });
                if let Some(i) = remove {
                    self.regions.remove(i);
                }
                if self.regions.is_empty() {
                    ui.label(egui::RichText::new("no regions — select bytes then Fold selection").color(theme::GREEN_DIM));
                }
            });
        self.regions_open = open;
    }

    fn inspector_panel(&mut self, ctx: &egui::Context) {
        if !self.inspector_open {
            return;
        }
        let mut open = self.inspector_open;
        egui::SidePanel::right("inspector")
            .resizable(true)
            .default_width(260.0)
            // Clamp the width so a long, unbreakable value (e.g. a denormalized
            // float string) can't grow the panel to fill the screen.
            .width_range(egui::Rangef::new(180.0, 460.0))
            .frame(egui::Frame::none().fill(theme::PANEL).inner_margin(8.0))
            .show(ctx, |ui| {
                ui.horizontal(|ui| {
                    ui.label(egui::RichText::new("DATA INSPECTOR").color(theme::GREEN).strong());
                    if ui.small_button("✕").clicked() {
                        open = false;
                    }
                });
                ui.horizontal(|ui| {
                    ui.label("byte order:");
                    ui.selectable_value(&mut self.inspector_le, true, "LE");
                    ui.selectable_value(&mut self.inspector_le, false, "BE");
                });
                ui.label(
                    egui::RichText::new(format!("@ {:#X}", self.cursor)).color(theme::ADDR),
                );
                ui.separator();
                let window = self.doc.read_range(self.cursor, 16);
                let interps = inspect::inspect(&window, self.inspector_le);
                egui::Grid::new("inspector_grid")
                    .num_columns(2)
                    .striped(true)
                    .show(ui, |ui| {
                        for it in &interps {
                            ui.label(egui::RichText::new(it.label).color(theme::GREEN_DIM));
                            // Truncate long, unbreakable values so the grid column
                            // can't force the panel wider; full value on hover.
                            ui.add(
                                egui::Label::new(
                                    egui::RichText::new(&it.value).color(theme::GREEN).monospace(),
                                )
                                .truncate(),
                            )
                            .on_hover_text(&it.value);
                            ui.end_row();
                        }
                    });
            });
        self.inspector_open = open;
    }

    fn transform_window(&mut self, ctx: &egui::Context) {
        let mut open = self.transform.open;
        egui::Window::new("Transform selection")
            .open(&mut open)
            .resizable(false)
            .show(ctx, |ui| {
                if self.selection_range().is_none() {
                    ui.label(
                        egui::RichText::new("select a range in the editor first")
                            .color(theme::AMBER),
                    );
                }
                egui::ComboBox::from_label("Operation")
                    .selected_text(TRANSFORM_OPS[self.transform.op].0)
                    .show_ui(ui, |ui| {
                        for (i, t) in TRANSFORM_OPS.iter().enumerate() {
                            ui.selectable_value(&mut self.transform.op, i, t.0);
                        }
                    });
                let (_, _, needs_key, needs_count) = TRANSFORM_OPS[self.transform.op];
                if needs_key {
                    ui.horizontal(|ui| {
                        ui.label("Key (hex byte):");
                        ui.text_edit_singleline(&mut self.transform.key);
                    });
                }
                if needs_count {
                    ui.horizontal(|ui| {
                        ui.label("Count (bits 0-8):");
                        ui.text_edit_singleline(&mut self.transform.key);
                    });
                }
                if matches!(TRANSFORM_OPS[self.transform.op].1, TKind::Swap) {
                    ui.horizontal(|ui| {
                        ui.label("Group size:");
                        for g in [2usize, 4, 8] {
                            ui.selectable_value(&mut self.transform.swap_group, g, format!("{g}"));
                        }
                    });
                }
                ui.separator();
                if ui
                    .add_enabled(self.selection_range().is_some(), egui::Button::new("Apply"))
                    .clicked()
                {
                    self.apply_transform();
                }
            });
        self.transform.open = open;
    }

    fn strings_window(&mut self, ctx: &egui::Context) {
        let mut open = self.strings.open;
        let mut jump: Option<u64> = None;
        egui::Window::new("Extract strings")
            .open(&mut open)
            .resizable(true)
            .default_width(520.0)
            .show(ctx, |ui| {
                ui.horizontal(|ui| {
                    ui.label("Min length:");
                    ui.add(egui::TextEdit::singleline(&mut self.strings.min_len).desired_width(48.0));
                    ui.checkbox(&mut self.strings.whole_file, "Whole file (else selection)");
                    if ui.button("Scan").clicked() {
                        self.do_strings();
                    }
                });
                ui.separator();
                ui.label(
                    egui::RichText::new(format!("{} result(s)", self.strings.results.len()))
                        .color(theme::GREEN_DIM),
                );
                egui::ScrollArea::vertical().max_height(360.0).show(ui, |ui| {
                    egui::Grid::new("strings_grid")
                        .num_columns(3)
                        .striped(true)
                        .show(ui, |ui| {
                            for f in &self.strings.results {
                                if ui
                                    .add(egui::Label::new(
                                        egui::RichText::new(format!("{:#010X}", f.offset))
                                            .color(theme::ADDR),
                                    )
                                    .sense(egui::Sense::click()))
                                    .clicked()
                                {
                                    jump = Some(f.offset);
                                }
                                let kind = match f.kind {
                                    crate::ops::strings::Kind::Ascii => "A",
                                    crate::ops::strings::Kind::Utf16 => "U",
                                };
                                ui.label(egui::RichText::new(kind).color(theme::GREEN_DIM));
                                ui.label(egui::RichText::new(&f.text).monospace());
                                ui.end_row();
                            }
                        });
                });
                ui.label(egui::RichText::new("click an offset to jump there").small().color(theme::GREEN_DIM));
            });
        if let Some(off) = jump {
            self.set_cursor(off, false);
        }
        self.strings.open = open;
    }

    fn scan_window(&mut self, ctx: &egui::Context) {
        let mut open = self.scan.open;
        let mut jump: Option<u64> = None;
        egui::Window::new("Value scanner")
            .open(&mut open)
            .resizable(true)
            .default_width(420.0)
            .show(ctx, |ui| {
                ui.label(
                    egui::RichText::new(
                        "First scan for a value, change it (in-game / by editing), then refine \
                         until one address remains.",
                    )
                    .small()
                    .color(theme::GREEN_DIM),
                );
                egui::ComboBox::from_label("Type")
                    .selected_text(TYPES[self.scan.data_type].0)
                    .show_ui(ui, |ui| {
                        for (i, t) in TYPES.iter().enumerate() {
                            ui.selectable_value(&mut self.scan.data_type, i, t.0);
                        }
                    });
                ui.horizontal(|ui| {
                    ui.label("Value:");
                    ui.text_edit_singleline(&mut self.scan.value);
                });
                ui.horizontal(|ui| {
                    ui.checkbox(&mut self.scan.aligned, "Aligned");
                    ui.checkbox(&mut self.scan.big_endian, "Big-endian");
                });
                ui.separator();
                ui.horizontal(|ui| {
                    if ui.button("First scan").clicked() {
                        self.do_first_scan();
                    }
                    if ui.button("Next: equal").clicked() {
                        if let Ok(n) = self.scan_needle() {
                            self.do_refine(scan::Refine::Eq(n));
                        }
                    }
                    if ui.button("Changed").clicked() {
                        self.do_refine(scan::Refine::Changed);
                    }
                    if ui.button("Unchanged").clicked() {
                        self.do_refine(scan::Refine::Unchanged);
                    }
                });
                ui.horizontal(|ui| {
                    if ui.button("Increased").clicked() {
                        self.do_refine(scan::Refine::Increased);
                    }
                    if ui.button("Decreased").clicked() {
                        self.do_refine(scan::Refine::Decreased);
                    }
                    if ui
                        .add_enabled(
                            !self.scan.matches.is_empty(),
                            egui::Button::new("Write value → all"),
                        )
                        .clicked()
                    {
                        self.poke_value();
                    }
                    if ui.button("Clear").clicked() {
                        self.scan.matches.clear();
                        self.scan.status.clear();
                    }
                });
                ui.horizontal(|ui| {
                    if ui
                        .add_enabled(
                            self.process_target.is_some() && !self.scan.matches.is_empty(),
                            egui::Button::new("❄ Freeze matches"),
                        )
                        .on_hover_text("keep re-writing the value into the live process")
                        .clicked()
                    {
                        self.freeze_matches();
                    }
                    if !self.frozen.is_empty() {
                        ui.label(
                            egui::RichText::new(format!("❄ {} frozen", self.frozen.len()))
                                .color(theme::RED),
                        );
                        if ui.button("Unfreeze all").clicked() {
                            self.unfreeze_all();
                        }
                    }
                });
                if !self.scan.status.is_empty() {
                    ui.label(egui::RichText::new(&self.scan.status).color(theme::AMBER));
                }
                ui.separator();
                let ty = TYPES[self.scan.data_type].1;
                let endian = self.scan_endian();
                egui::ScrollArea::vertical().max_height(300.0).show(ui, |ui| {
                    egui::Grid::new("scan_grid").num_columns(2).striped(true).show(ui, |ui| {
                        for m in self.scan.matches.iter().take(2000) {
                            if ui
                                .add(egui::Label::new(
                                    egui::RichText::new(format!("{:#010X}", m.offset))
                                        .color(theme::ADDR),
                                ).sense(egui::Sense::click()))
                                .clicked()
                            {
                                jump = Some(m.offset);
                            }
                            ui.label(
                                egui::RichText::new(scan_value_str(&m.bytes, ty, endian))
                                    .monospace(),
                            );
                            ui.end_row();
                        }
                    });
                });
                if self.scan.matches.len() > 2000 {
                    ui.label(
                        egui::RichText::new(format!(
                            "(showing first 2000 of {})",
                            self.scan.matches.len()
                        ))
                        .small()
                        .color(theme::GREEN_DIM),
                    );
                }
            });
        if let Some(off) = jump {
            self.set_cursor(off, false);
        }
        self.scan.open = open;
    }

    fn ptrscan_window(&mut self, ctx: &egui::Context) {
        let mut open = self.ptrscan.open;
        let mut jump: Option<u64> = None;
        egui::Window::new("Pointer scan")
            .open(&mut open)
            .resizable(true)
            .default_width(420.0)
            .show(ctx, |ui| {
                ui.label(
                    egui::RichText::new(
                        "Find 64-bit pointers into [target-maxoff, target]. Base = address of \
                         byte 0 of this image (0 for a file).",
                    )
                    .small()
                    .color(theme::GREEN_DIM),
                );
                egui::Grid::new("ptrscan_in").num_columns(2).show(ui, |ui| {
                    ui.label("Target addr");
                    ui.add(egui::TextEdit::singleline(&mut self.ptrscan.target).hint_text("0x…"));
                    ui.end_row();
                    ui.label("Image base");
                    ui.add(egui::TextEdit::singleline(&mut self.ptrscan.base).hint_text("0"));
                    ui.end_row();
                    ui.label("Max offset");
                    ui.add(egui::TextEdit::singleline(&mut self.ptrscan.max_offset));
                    ui.end_row();
                });
                ui.horizontal(|ui| {
                    if ui.button("Scan").clicked() {
                        self.do_ptrscan();
                    }
                    if !self.ptrscan.status.is_empty() {
                        ui.label(egui::RichText::new(&self.ptrscan.status).color(theme::AMBER));
                    }
                });
                ui.separator();
                egui::ScrollArea::vertical().max_height(300.0).show(ui, |ui| {
                    egui::Grid::new("ptrscan_out").num_columns(2).striped(true).show(ui, |ui| {
                        ui.label(egui::RichText::new("pointer addr").color(theme::ADDR));
                        ui.label(egui::RichText::new("offset").color(theme::ADDR));
                        ui.end_row();
                        for (addr, off) in self.ptrscan.results.iter().take(2000) {
                            if ui
                                .add(egui::Label::new(
                                    egui::RichText::new(format!("{:#018X}", addr)).color(theme::GREEN),
                                ).sense(egui::Sense::click()))
                                .clicked()
                            {
                                jump = Some(*addr);
                            }
                            ui.label(egui::RichText::new(format!("+{:#X}", off)).monospace());
                            ui.end_row();
                        }
                    });
                });
            });
        if let Some(addr) = jump {
            // jump to the pointer's document offset (addr - base)
            let base = self.ptrscan.base.trim().trim_start_matches("0x");
            let base = u64::from_str_radix(base, 16).ok().or_else(|| self.ptrscan.base.trim().parse().ok()).unwrap_or(0);
            self.set_cursor(addr.saturating_sub(base).min(self.doc.len()), false);
        }
        self.ptrscan.open = open;
    }

    fn signatures_window(&mut self, ctx: &egui::Context) {
        let mut open = self.signatures.open;
        let mut jump: Option<u64> = None;
        egui::Window::new("Signatures (binwalk)")
            .open(&mut open)
            .resizable(true)
            .default_width(460.0)
            .show(ctx, |ui| {
                ui.horizontal(|ui| {
                    if ui.button("Scan file").clicked() {
                        self.do_signatures();
                    }
                    ui.label(
                        egui::RichText::new(format!("{} hit(s)", self.signatures.results.len()))
                            .color(theme::GREEN_DIM),
                    );
                });
                ui.separator();
                egui::ScrollArea::vertical().max_height(360.0).show(ui, |ui| {
                    egui::Grid::new("sig_grid").num_columns(3).striped(true).show(ui, |ui| {
                        for h in &self.signatures.results {
                            if ui
                                .add(egui::Label::new(
                                    egui::RichText::new(format!("{:#010X}", h.offset))
                                        .color(theme::ADDR),
                                ).sense(egui::Sense::click()))
                                .clicked()
                            {
                                jump = Some(h.offset);
                            }
                            ui.label(
                                egui::RichText::new(h.category.label()).color(theme::GREEN_DIM),
                            );
                            ui.label(egui::RichText::new(h.name).color(theme::GREEN));
                            ui.end_row();
                        }
                    });
                });
                ui.label(
                    egui::RichText::new("detects embedded formats, archives, executables and crypto constants")
                        .small()
                        .color(theme::GREEN_DIM),
                );
            });
        if let Some(off) = jump {
            self.set_cursor(off, false);
        }
        self.signatures.open = open;
    }

    fn byteplot_window(&mut self, ctx: &egui::Context) {
        let mut open = self.byteplot.open;
        let mut render = false;
        let mut jump: Option<u64> = None;
        let len = self.doc.len();
        egui::Window::new("Byte map")
            .open(&mut open)
            .resizable(true)
            .show(ctx, |ui| {
                ui.horizontal(|ui| {
                    if ui.button("Render").clicked() {
                        render = true;
                    }
                    ui.label(
                        egui::RichText::new("each pixel = one byte (sampled), colored by class")
                            .small()
                            .color(theme::GREEN_DIM),
                    );
                });
                if let Some(tex) = &self.byteplot.texture {
                    let side = 512.0;
                    let resp = ui.add(
                        egui::Image::new(tex)
                            .fit_to_exact_size(egui::vec2(side, side))
                            .sense(egui::Sense::click()),
                    );
                    if resp.clicked() {
                        if let Some(pos) = resp.interact_pointer_pos() {
                            let rect = resp.rect;
                            let fx = ((pos.x - rect.left()) / rect.width()).clamp(0.0, 0.999);
                            let fy = ((pos.y - rect.top()) / rect.height()).clamp(0.0, 0.999);
                            let (w, h) = (self.byteplot.width, self.byteplot.height);
                            let px = (fy * h as f32) as u64 * w as u64 + (fx * w as f32) as u64;
                            jump = Some(byteplot::sample_offset(px, (w * h) as u64, len).min(len));
                        }
                    }
                    ui.label(
                        egui::RichText::new("click a pixel to jump there").small().color(theme::GREEN_DIM),
                    );
                } else {
                    ui.label(egui::RichText::new("press Render").color(theme::GREEN_DIM));
                }
            });
        if render {
            self.build_byteplot(ctx);
        }
        if let Some(off) = jump {
            self.set_cursor(off, false);
        }
        self.byteplot.open = open;
    }

    fn diff_window(&mut self, ctx: &egui::Context) {
        let mut open = self.diff.open;
        let mut jump: Option<u64> = None;
        egui::Window::new("Compare / diff")
            .open(&mut open)
            .resizable(true)
            .default_width(460.0)
            .show(ctx, |ui| {
                ui.horizontal(|ui| {
                    if ui.button("Pick file & diff").clicked() {
                        self.do_diff();
                    }
                    if let Some(p) = &self.diff.other {
                        ui.label(
                            egui::RichText::new(p.file_name().unwrap_or_default().to_string_lossy())
                                .color(theme::ADDR),
                        );
                    }
                });
                if !self.diff.status.is_empty() {
                    ui.label(egui::RichText::new(&self.diff.status).color(theme::AMBER));
                }
                ui.separator();
                egui::ScrollArea::vertical().max_height(360.0).show(ui, |ui| {
                    egui::Grid::new("diff_grid").num_columns(2).striped(true).show(ui, |ui| {
                        ui.label(egui::RichText::new("offset").color(theme::ADDR));
                        ui.label(egui::RichText::new("length").color(theme::ADDR));
                        ui.end_row();
                        for r in &self.diff.ranges {
                            if ui
                                .add(egui::Label::new(
                                    egui::RichText::new(format!("{:#010X}", r.offset))
                                        .color(theme::GREEN),
                                ).sense(egui::Sense::click()))
                                .clicked()
                            {
                                jump = Some(r.offset);
                            }
                            ui.label(egui::RichText::new(format!("{}", r.len)).monospace());
                            ui.end_row();
                        }
                    });
                });
                ui.label(egui::RichText::new("click an offset to jump there").small().color(theme::GREEN_DIM));
            });
        if let Some(off) = jump {
            self.set_cursor(off, false);
        }
        self.diff.open = open;
    }

    fn disasm_window(&mut self, ctx: &egui::Context) {
        let mut open = self.disasm.open;
        let mut jump: Option<u64> = None;
        egui::Window::new("Disassembly")
            .open(&mut open)
            .resizable(true)
            .default_width(460.0)
            .show(ctx, |ui| {
                ui.horizontal_wrapped(|ui| {
                    ui.label("Arch:");
                    for a in disasm::Arch::ALL {
                        ui.selectable_value(&mut self.disasm.arch, *a, a.label());
                    }
                });
                ui.label(
                    egui::RichText::new(format!("from cursor {:#X}", self.cursor))
                        .color(theme::ADDR),
                );
                ui.separator();
                let ins = disasm::disassemble(&self.doc, self.cursor, 64, self.disasm.arch);
                egui::ScrollArea::vertical().max_height(400.0).show(ui, |ui| {
                    egui::Grid::new("disasm_grid").num_columns(3).striped(true).show(ui, |ui| {
                        for i in &ins {
                            if ui
                                .add(egui::Label::new(
                                    egui::RichText::new(format!("{:08X}", i.offset))
                                        .color(theme::ADDR),
                                ).sense(egui::Sense::click()))
                                .clicked()
                            {
                                jump = Some(i.offset);
                            }
                            let hex: String =
                                i.bytes.iter().map(|b| format!("{:02X}", b)).collect::<Vec<_>>().join(" ");
                            ui.label(egui::RichText::new(hex).color(theme::GREEN_DIM).monospace());
                            ui.label(egui::RichText::new(&i.text).color(theme::GREEN).monospace());
                            ui.end_row();
                        }
                    });
                });
                if ins.is_empty() {
                    ui.label(egui::RichText::new("nothing to decode at the cursor").color(theme::GREEN_DIM));
                }
            });
        if let Some(off) = jump {
            self.set_cursor(off, false);
        }
        self.disasm.open = open;
    }

    fn kstruct_window(&mut self, ctx: &egui::Context) {
        use crate::ops::kstruct;
        let mut open = self.kstruct.open;
        let mut jump: Option<u64> = None;
        egui::Window::new("Struct parser")
            .open(&mut open)
            .resizable(true)
            .default_width(620.0)
            .show(ctx, |ui| {
                ui.horizontal(|ui| {
                    egui::ComboBox::from_label("Built-in")
                        .selected_text(kstruct::BUILTINS[self.kstruct.builtin].0)
                        .show_ui(ui, |ui| {
                            for (i, (name, _)) in kstruct::BUILTINS.iter().enumerate() {
                                if ui.selectable_value(&mut self.kstruct.builtin, i, *name).clicked() {
                                    self.kstruct.src = kstruct::BUILTINS[i].1.to_string();
                                }
                            }
                        });
                    if ui.button("Parse at cursor").clicked() {
                        self.apply_kstruct();
                    }
                });
                ui.collapsing("schema (editable DSL — sub-types, repeat, if, enums)", |ui| {
                    ui.add(
                        egui::TextEdit::multiline(&mut self.kstruct.src)
                            .font(egui::TextStyle::Monospace)
                            .desired_rows(8)
                            .desired_width(f32::INFINITY),
                    );
                });
                if !self.kstruct.status.is_empty() {
                    ui.label(
                        egui::RichText::new(&self.kstruct.status)
                            .color(theme::status_color(&self.kstruct.status)),
                    );
                }
                ui.separator();
                egui::ScrollArea::vertical().max_height(380.0).show(ui, |ui| {
                    if let Some(root) = &self.kstruct.tree {
                        for c in &root.children {
                            kstruct_node_ui(ui, c, &mut jump);
                        }
                    } else {
                        ui.label(egui::RichText::new("press Parse").color(theme::GREEN_DIM));
                    }
                });
            });
        if let Some(off) = jump {
            self.set_cursor(off.min(self.doc.len()), false);
        }
        self.kstruct.open = open;
    }

    fn template_window(&mut self, ctx: &egui::Context) {
        let mut open = self.template.open;
        let mut jump: Option<u64> = None;
        egui::Window::new("Binary template")
            .open(&mut open)
            .resizable(true)
            .default_width(560.0)
            .show(ctx, |ui| {
                ui.horizontal(|ui| {
                    egui::ComboBox::from_label("Built-in")
                        .selected_text(template::BUILTINS[self.template.builtin].0)
                        .show_ui(ui, |ui| {
                            for (i, (name, _)) in template::BUILTINS.iter().enumerate() {
                                if ui
                                    .selectable_value(&mut self.template.builtin, i, *name)
                                    .clicked()
                                {
                                    self.template.src = template::BUILTINS[i].1.to_string();
                                }
                            }
                        });
                    if ui.button("Apply at cursor").clicked() {
                        self.apply_template();
                    }
                });
                ui.collapsing("template source (editable DSL)", |ui| {
                    ui.add(
                        egui::TextEdit::multiline(&mut self.template.src)
                            .font(egui::TextStyle::Monospace)
                            .desired_rows(8)
                            .desired_width(f32::INFINITY),
                    );
                });
                if !self.template.status.is_empty() {
                    ui.label(egui::RichText::new(&self.template.status).color(theme::status_color(&self.template.status)));
                }
                // Inline editor for the selected field.
                let mut do_write = false;
                if let Some(idx) = self.template.edit_idx {
                    if let Some(f) = self.template.fields.get(idx) {
                        ui.separator();
                        ui.horizontal(|ui| {
                            ui.label(
                                egui::RichText::new(format!("edit {} ({}):", f.name, f.kind))
                                    .color(theme::AMBER),
                            );
                            let resp = ui.add(
                                egui::TextEdit::singleline(&mut self.template.edit_buf)
                                    .desired_width(160.0),
                            );
                            if ui.button("Write").clicked()
                                || (resp.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter)))
                            {
                                do_write = true;
                            }
                            if ui.button("Cancel").clicked() {
                                self.template.edit_idx = None;
                            }
                        });
                    }
                }
                ui.separator();
                let mut start_edit: Option<(usize, String)> = None;
                egui::ScrollArea::vertical().max_height(340.0).show(ui, |ui| {
                    egui::Grid::new("tmpl_grid").num_columns(5).striped(true).show(ui, |ui| {
                        ui.label(egui::RichText::new("offset").color(theme::ADDR));
                        ui.label(egui::RichText::new("field").color(theme::ADDR));
                        ui.label(egui::RichText::new("type").color(theme::ADDR));
                        ui.label(egui::RichText::new("value").color(theme::ADDR));
                        ui.label("");
                        ui.end_row();
                        for (i, f) in self.template.fields.iter().enumerate() {
                            if ui
                                .add(egui::Label::new(
                                    egui::RichText::new(format!("{:#010X}", f.offset))
                                        .color(theme::GREEN),
                                ).sense(egui::Sense::click()))
                                .clicked()
                            {
                                jump = Some(f.offset);
                            }
                            ui.label(egui::RichText::new(&f.name).color(theme::GREEN));
                            ui.label(egui::RichText::new(&f.kind).color(theme::GREEN_DIM));
                            ui.label(egui::RichText::new(&f.value).monospace());
                            if f.edit != template::EditKind::None {
                                if ui.small_button("edit").clicked() {
                                    start_edit = Some((i, f.value.clone()));
                                }
                            } else {
                                ui.label("");
                            }
                            ui.end_row();
                        }
                    });
                });
                if let Some((i, val)) = start_edit {
                    self.template.edit_idx = Some(i);
                    self.template.edit_buf = val;
                }
                if do_write {
                    if let Some(idx) = self.template.edit_idx {
                        self.write_template_field(idx);
                    }
                }
            });
        if let Some(off) = jump {
            self.set_cursor(off, false);
        }
        self.template.open = open;
    }

    fn script_window(&mut self, ctx: &egui::Context) {
        let mut open = self.script.open;
        egui::Window::new("Script (Rhai)")
            .open(&mut open)
            .resizable(true)
            .default_width(560.0)
            .show(ctx, |ui| {
                let mut load_src: Option<String> = None;
                ui.horizontal(|ui| {
                    if ui.button("Run").clicked() {
                        self.run_script();
                    }
                    ui.checkbox(&mut self.script.whole_file, "Whole file (else selection)");
                    egui::ComboBox::from_label("Load")
                        .selected_text("library / saved")
                        .show_ui(ui, |ui| {
                            ui.label(egui::RichText::new("built-in").color(theme::GREEN_DIM));
                            for (name, src) in crate::ops::script::LIBRARY {
                                if ui.selectable_label(false, *name).clicked() {
                                    load_src = Some(src.to_string());
                                }
                            }
                            let user = crate::ops::script_store::list();
                            if !user.is_empty() {
                                ui.separator();
                                ui.label(egui::RichText::new("saved").color(theme::GREEN_DIM));
                                for (name, _) in &user {
                                    if ui.selectable_label(false, name).clicked() {
                                        load_src = crate::ops::script_store::load(name);
                                    }
                                }
                            }
                        });
                });
                if let Some(s) = load_src {
                    self.script.src = s;
                }
                ui.horizontal(|ui| {
                    ui.label("Save as:");
                    ui.add(
                        egui::TextEdit::singleline(&mut self.script.save_name)
                            .desired_width(160.0)
                            .hint_text("name"),
                    );
                    if ui.button("Save script").clicked() {
                        match crate::ops::script_store::save(&self.script.save_name, &self.script.src) {
                            Ok(p) => self.script.output = format!("saved {}", p.display()),
                            Err(e) => self.script.output = format!("save failed: {e}"),
                        }
                    }
                });
                ui.separator();
                egui::ScrollArea::vertical().max_height(260.0).id_salt("script_src").show(ui, |ui| {
                    ui.add(
                        egui::TextEdit::multiline(&mut self.script.src)
                            .font(egui::TextStyle::Monospace)
                            .desired_rows(12)
                            .desired_width(f32::INFINITY)
                            .code_editor(),
                    );
                });
                if !self.script.output.is_empty() {
                    ui.separator();
                    ui.label(
                        egui::RichText::new("output")
                            .small()
                            .color(theme::GREEN_DIM),
                    );
                    egui::ScrollArea::vertical().max_height(140.0).id_salt("script_out").show(ui, |ui| {
                        ui.add(
                            egui::TextEdit::multiline(&mut self.script.output.as_str())
                                .font(egui::TextStyle::Monospace)
                                .desired_width(f32::INFINITY),
                        );
                    });
                }
            });
        self.script.open = open;
    }

    fn process_window(&mut self, ctx: &egui::Context) {
        let mut open = self.process_ui.open;
        let mut pick: Option<(u64, u64)> = None;
        egui::Window::new("Open process memory")
            .open(&mut open)
            .resizable(true)
            .default_width(520.0)
            .show(ctx, |ui| {
                // Loud, unmissable privilege banner.
                let elevated = crate::data::is_elevated();
                let own = crate::data::own_pid();
                egui::Frame::none()
                    .fill(theme::BG_ALT)
                    .stroke(egui::Stroke::new(1.0, theme::RED))
                    .inner_margin(8.0)
                    .rounding(2.0)
                    .show(ui, |ui| {
                        ui.label(
                            egui::RichText::new("⚠  ADMINISTRATOR / ROOT REQUIRED")
                                .color(theme::RED)
                                .strong(),
                        );
                        ui.label(
                            egui::RichText::new(
                                "Reading or writing ANOTHER process's memory needs elevated \
                                 privileges. Your own PID works without them.",
                            )
                            .color(theme::AMBER),
                        );
                        ui.label(
                            egui::RichText::new(crate::data::privilege_note())
                                .small()
                                .color(theme::GREEN_DIM),
                        );
                        let status = if elevated {
                            egui::RichText::new("● running ELEVATED — you can attach to other processes")
                                .color(theme::GREEN)
                        } else {
                            egui::RichText::new(format!(
                                "● running UNPRIVILEGED — only your own PID ({own}) is openable; \
                                 relaunch with sudo / as Administrator for others"
                            ))
                            .color(theme::RED)
                        };
                        ui.label(status);
                    });
                ui.add_space(4.0);
                ui.horizontal(|ui| {
                    ui.label("PID:");
                    ui.add(egui::TextEdit::singleline(&mut self.process_ui.pid).desired_width(80.0));
                    if ui.button("List regions").clicked() {
                        self.list_process_regions();
                    }
                    if ui.button(format!("use self ({})", std::process::id())).clicked() {
                        self.process_ui.pid = std::process::id().to_string();
                        self.list_process_regions();
                    }
                });
                ui.horizontal(|ui| {
                    ui.label("Base:");
                    ui.add(egui::TextEdit::singleline(&mut self.process_ui.base).desired_width(140.0));
                    ui.label("Length:");
                    ui.add(egui::TextEdit::singleline(&mut self.process_ui.len).desired_width(100.0));
                    if ui.button("Open live view").clicked() {
                        self.open_process();
                    }
                });
                if !self.process_ui.status.is_empty() {
                    ui.label(
                        egui::RichText::new(&self.process_ui.status)
                            .color(theme::status_color(&self.process_ui.status)),
                    );
                }
                ui.separator();
                egui::ScrollArea::vertical().max_height(320.0).show(ui, |ui| {
                    egui::Grid::new("proc_regions").num_columns(3).striped(true).show(ui, |ui| {
                        ui.label(egui::RichText::new("base").color(theme::ADDR));
                        ui.label(egui::RichText::new("size").color(theme::ADDR));
                        ui.label(egui::RichText::new("perms").color(theme::ADDR));
                        ui.end_row();
                        for r in &self.process_ui.regions {
                            if ui
                                .add(egui::Label::new(
                                    egui::RichText::new(format!("{:#018X}", r.base))
                                        .color(theme::GREEN),
                                ).sense(egui::Sense::click()))
                                .on_hover_text("click to load base/length")
                                .clicked()
                            {
                                pick = Some((r.base, r.size));
                            }
                            ui.label(egui::RichText::new(human(r.size)).monospace());
                            let perms = format!(
                                "{}{}{}",
                                if r.readable { "r" } else { "-" },
                                if r.writable { "w" } else { "-" },
                                if r.executable { "x" } else { "-" },
                            );
                            ui.label(egui::RichText::new(perms).color(theme::GREEN_DIM));
                            ui.end_row();
                        }
                    });
                });
            });
        if let Some((base, size)) = pick {
            self.process_ui.base = format!("{:#X}", base);
            self.process_ui.len = format!("{}", size.min(1 << 24)); // cap default to 16 MiB
        }
        self.process_ui.open = open;
    }

    fn notes_window(&mut self, ctx: &egui::Context) {
        let mut open = self.notes_open;
        let mut jump: Option<u64> = None;
        let mut remove: Option<usize> = None;
        egui::Window::new("Notes / annotations")
            .open(&mut open)
            .resizable(true)
            .default_width(520.0)
            .show(ctx, |ui| {
                ui.horizontal(|ui| {
                    ui.label("Note:");
                    ui.add(
                        egui::TextEdit::singleline(&mut self.note_input)
                            .desired_width(280.0)
                            .hint_text("text…"),
                    );
                    let target = self
                        .selection_range()
                        .map(|(s, e)| format!("{:#X}..{:#X}", s, e))
                        .unwrap_or_else(|| format!("@ {:#X}", self.cursor));
                    if ui.button(format!("Add {target}")).clicked() {
                        self.add_note();
                    }
                });
                ui.label(
                    egui::RichText::new(
                        "notes are saved to <file>.ghx via File ▸ Save annotations, and \
                         auto-loaded when you reopen the file",
                    )
                    .small()
                    .color(theme::GREEN_DIM),
                );
                ui.separator();
                egui::ScrollArea::vertical().max_height(320.0).show(ui, |ui| {
                    egui::Grid::new("notes_grid").num_columns(4).striped(true).show(ui, |ui| {
                        ui.label(egui::RichText::new("offset").color(theme::ADDR));
                        ui.label(egui::RichText::new("len").color(theme::ADDR));
                        ui.label(egui::RichText::new("note").color(theme::ADDR));
                        ui.label("");
                        ui.end_row();
                        for (i, n) in self.notes.iter().enumerate() {
                            if ui
                                .add(egui::Label::new(
                                    egui::RichText::new(format!("{:#010X}", n.offset))
                                        .color(theme::GREEN),
                                ).sense(egui::Sense::click()))
                                .clicked()
                            {
                                jump = Some(n.offset);
                            }
                            ui.label(egui::RichText::new(format!("{}", n.len)).monospace());
                            ui.label(egui::RichText::new(&n.text));
                            if ui.small_button("✕").clicked() {
                                remove = Some(i);
                            }
                            ui.end_row();
                        }
                    });
                });
                if self.notes.is_empty() {
                    ui.label(egui::RichText::new("no notes yet").color(theme::GREEN_DIM));
                }
            });
        if let Some(i) = remove {
            self.notes.remove(i);
        }
        if let Some(off) = jump {
            self.set_cursor(off, false);
        }
        self.notes_open = open;
    }

    fn about_window(&mut self, ctx: &egui::Context) {
        let mut open = self.about_open;
        egui::Window::new("About ganghex")
            .open(&mut open)
            .resizable(false)
            .show(ctx, |ui| {
                ui.label(egui::RichText::new("ganghex 0.1.0").heading().color(theme::GREEN));
                ui.label("a fast, cross-platform, hacker-esque hex editor");
                ui.label("for files, raw disks and RAM — up to 8 EB.");
                ui.separator();
                ui.label(egui::RichText::new("piece-table engine · mmap · unlimited undo").color(theme::GREEN_DIM));
                ui.label(egui::RichText::new("egui · pure Rust").color(theme::GREEN_DIM));
            });
        self.about_open = open;
    }

    fn progress_window(&mut self, ctx: &egui::Context) {
        let Some(task) = &self.bg else { return };
        let frac = task.progress.fraction();
        let elapsed = task.started.elapsed().as_secs_f32();
        let eta = if frac > 0.001 {
            elapsed * (1.0 - frac) / frac
        } else {
            f32::NAN
        };
        let label = task.label.clone();
        let mut cancel = false;
        egui::Window::new("working…")
            .collapsible(false)
            .resizable(false)
            .anchor(egui::Align2::CENTER_CENTER, egui::vec2(0.0, 0.0))
            .show(ctx, |ui| {
                ui.label(egui::RichText::new(&label).color(theme::AMBER));
                ui.add(egui::ProgressBar::new(frac).show_percentage().desired_width(320.0));
                ui.label(format!(
                    "elapsed {:.1}s   ·   remaining {}",
                    elapsed,
                    if eta.is_finite() {
                        format!("{:.1}s", eta)
                    } else {
                        "…".into()
                    }
                ));
                if ui.button("Cancel").clicked() {
                    cancel = true;
                }
            });
        if cancel {
            if let Some(t) = &self.bg {
                t.progress.cancel();
            }
        }
        ctx.request_repaint_after(std::time::Duration::from_millis(60));
    }
}

// ---- free helpers ----

fn digit_of(key: Key) -> Option<usize> {
    Some(match key {
        Key::Num0 => 0,
        Key::Num1 => 1,
        Key::Num2 => 2,
        Key::Num3 => 3,
        Key::Num4 => 4,
        Key::Num5 => 5,
        Key::Num6 => 6,
        Key::Num7 => 7,
        Key::Num8 => 8,
        Key::Num9 => 9,
        _ => return None,
    })
}

/// Render a scanner match's bytes as its typed value for display.
fn scan_value_str(bytes: &[u8], ty: search::DataType, endian: search::Endian) -> String {
    use search::DataType::*;
    let le = endian == search::Endian::Little;
    let rd = |n: usize| -> Option<u64> {
        if bytes.len() < n {
            return None;
        }
        let mut v = 0u64;
        if le {
            for i in (0..n).rev() {
                v = (v << 8) | bytes[i] as u64;
            }
        } else {
            for &b in bytes.iter().take(n) {
                v = (v << 8) | b as u64;
            }
        }
        Some(v)
    };
    let sx = |v: u64, n: usize| -> i64 {
        let shift = 64 - n * 8;
        ((v << shift) as i64) >> shift
    };
    match ty {
        I8 => rd(1).map(|v| sx(v, 1).to_string()),
        I16 => rd(2).map(|v| sx(v, 2).to_string()),
        I32 => rd(4).map(|v| sx(v, 4).to_string()),
        I64 => rd(8).map(|v| sx(v, 8).to_string()),
        F32 => rd(4).map(|v| f32::from_bits(v as u32).to_string()),
        F64 => rd(8).map(|v| f64::from_bits(v).to_string()),
        _ => Some(
            bytes
                .iter()
                .map(|b| format!("{:02X}", b))
                .collect::<Vec<_>>()
                .join(" "),
        ),
    }
    .unwrap_or_else(|| "—".to_string())
}

fn parse_addr(s: &str) -> Option<u64> {
    let s = s.trim();
    if let Some(h) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        u64::from_str_radix(h, 16).ok()
    } else if s.chars().all(|c| c.is_ascii_hexdigit()) && s.chars().any(|c| c.is_ascii_alphabetic()) {
        u64::from_str_radix(s, 16).ok()
    } else {
        s.parse::<u64>().ok().or_else(|| u64::from_str_radix(s, 16).ok())
    }
}

fn draw_distribution(ui: &mut egui::Ui, counts: &[u64; 256]) {
    let max = counts.iter().copied().max().unwrap_or(1).max(1) as f32;
    let h = 120.0;
    let (rect, _) = ui.allocate_exact_size(egui::vec2(ui.available_width().min(528.0), h), Sense::hover());
    let painter = ui.painter_at(rect);
    painter.rect_filled(rect, 0.0, theme::PANEL);
    let bw = rect.width() / 256.0;
    for (i, &c) in counts.iter().enumerate() {
        if c == 0 {
            continue;
        }
        let bh = (c as f32 / max) * (h - 2.0);
        let x = rect.left() + i as f32 * bw;
        let bar = egui::Rect::from_min_max(
            egui::pos2(x, rect.bottom() - bh),
            egui::pos2(x + bw.max(1.0), rect.bottom()),
        );
        let color = if i == 0 || i == 0xff {
            theme::AMBER
        } else if (0x20..0x7f).contains(&i) {
            theme::GREEN
        } else {
            theme::GREEN_DIM
        };
        painter.rect_filled(bar, 0.0, color);
    }
}

/// Recursively render a kstruct node. Containers are collapsible; clicking a
/// node's offset jumps the cursor there.
fn kstruct_node_ui(ui: &mut egui::Ui, node: &crate::ops::kstruct::Node, jump: &mut Option<u64>) {
    let header = |ui: &mut egui::Ui| {
        if ui
            .add(egui::Label::new(
                egui::RichText::new(format!("{:#X}", node.offset)).color(theme::ADDR),
            ).sense(egui::Sense::click()))
            .clicked()
        {
            *jump = Some(node.offset);
        }
        ui.label(egui::RichText::new(&node.name).color(theme::GREEN));
        ui.label(egui::RichText::new(&node.kind).color(theme::GREEN_DIM));
        if !node.value.is_empty() {
            ui.label(egui::RichText::new(format!("= {}", node.value)).monospace());
        }
    };
    if node.children.is_empty() {
        ui.horizontal(header);
    } else {
        let id = ui.make_persistent_id((node.offset, node.name.as_str()));
        egui::collapsing_header::CollapsingState::load_with_default_open(ui.ctx(), id, false)
            .show_header(ui, header)
            .body(|ui| {
                for c in &node.children {
                    kstruct_node_ui(ui, c, jump);
                }
            });
    }
}

/// Draw the entropy strip (0..8 bits mapped green→amber→red). Returns the
/// clicked fraction along the strip, if any.
fn draw_entropy_map(ui: &mut egui::Ui, emap: &[f32]) -> Option<f32> {
    let h = 36.0;
    let (rect, resp) = ui.allocate_exact_size(
        egui::vec2(ui.available_width().min(528.0), h),
        Sense::click(),
    );
    let painter = ui.painter_at(rect);
    painter.rect_filled(rect, 0.0, theme::PANEL);
    let n = emap.len().max(1);
    let bw = rect.width() / n as f32;
    for (i, &e) in emap.iter().enumerate() {
        let t = (e / 8.0).clamp(0.0, 1.0);
        // green (low) -> amber -> red (high)
        let color = if t < 0.5 {
            let k = t * 2.0;
            egui::Color32::from_rgb(
                (0x33 as f32 + k * (0xff - 0x33) as f32) as u8,
                0xb8,
                (0x66 as f32 * (1.0 - k)) as u8,
            )
        } else {
            let k = (t - 0.5) * 2.0;
            egui::Color32::from_rgb(0xff, (0xb8 as f32 * (1.0 - k)) as u8, 0x4d)
        };
        let x = rect.left() + i as f32 * bw;
        painter.rect_filled(
            egui::Rect::from_min_max(
                egui::pos2(x, rect.top()),
                egui::pos2(x + bw.max(1.0), rect.bottom()),
            ),
            0.0,
            color,
        );
    }
    if resp.clicked() {
        if let Some(pos) = resp.interact_pointer_pos() {
            return Some(((pos.x - rect.left()) / rect.width()).clamp(0.0, 1.0));
        }
    }
    None
}

/// Platform-specific raw device targets offered in the File menu.
fn raw_targets() -> Vec<(String, String)> {
    #[cfg(target_os = "macos")]
    {
        vec![
            ("Whole disk 0 (/dev/rdisk0)".into(), "/dev/rdisk0".into()),
            ("Disk 1 (/dev/rdisk1)".into(), "/dev/rdisk1".into()),
        ]
    }
    #[cfg(target_os = "linux")]
    {
        vec![
            ("First disk (/dev/sda)".into(), "/dev/sda".into()),
            ("NVMe 0 (/dev/nvme0n1)".into(), "/dev/nvme0n1".into()),
            ("Physical RAM (/dev/mem)".into(), "/dev/mem".into()),
        ]
    }
    #[cfg(target_os = "windows")]
    {
        vec![
            ("Physical drive 0".into(), "\\\\.\\PhysicalDrive0".into()),
            ("Volume C:".into(), "\\\\.\\C:".into()),
        ]
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
    {
        Vec::new()
    }
}

#[cfg(test)]
mod ui_tests {
    use super::*;

    #[test]
    fn parse_addr_forms() {
        assert_eq!(parse_addr("0x10"), Some(16));
        assert_eq!(parse_addr("0X1F"), Some(31));
        assert_eq!(parse_addr("255"), Some(255));
        assert_eq!(parse_addr("deadbeef"), Some(0xdeadbeef)); // bare hex with letters
        assert_eq!(parse_addr("  0x100  "), Some(256));
        assert_eq!(parse_addr("zzz"), None);
    }

    #[test]
    fn human_sizes() {
        assert_eq!(human(0), "0 B");
        assert_eq!(human(512), "512 B");
        assert!(human(1024).starts_with("1.00 KiB"));
        assert!(human(1024 * 1024).starts_with("1.00 MiB"));
        assert!(human(1u64 << 60).contains("EiB"));
    }

    #[test]
    fn rebase_inserts_shifts_carets() {
        // carets at 5 and 10, each inserts 1 byte
        assert_eq!(rebase_inserts(&[5, 10], 1), vec![6, 12]);
        // single caret: just advances by n
        assert_eq!(rebase_inserts(&[3], 4), vec![7]);
        // three carets inserting 2 bytes each: earlier insertions push later carets
        // 0 -> 2 ; 4 shifted by +2 then +2 own -> 8 ; 8 shifted by +4 then +2 -> 14
        assert_eq!(rebase_inserts(&[0, 4, 8], 2), vec![2, 8, 14]);
        // order of input doesn't matter (positions are matched individually)
        assert_eq!(rebase_inserts(&[10, 5], 1), vec![12, 6]);
    }

    #[test]
    fn rebase_deletes_before_carets() {
        // backspace at 3 and 7 -> delete idx2,idx6 -> carets at 2 and 5
        assert_eq!(rebase_deletes_before(&[3, 7]), vec![2, 5]);
        // a caret at 0 cannot backspace and stays put
        assert_eq!(rebase_deletes_before(&[0, 5]), vec![0, 4]);
        assert_eq!(rebase_deletes_before(&[1]), vec![0]);
    }

    #[test]
    fn rebase_deletes_at_carets() {
        // delete-forward at 3 and 7 -> stay at 3, and 7 shifts left by one -> 6
        assert_eq!(rebase_deletes_at(&[3, 7]), vec![3, 6]);
        // adjacent carets collapse
        assert_eq!(rebase_deletes_at(&[0, 1, 2]), vec![0, 0, 0]);
    }

    #[test]
    fn digit_of_keys() {
        assert_eq!(digit_of(egui::Key::Num0), Some(0));
        assert_eq!(digit_of(egui::Key::Num9), Some(9));
        assert_eq!(digit_of(egui::Key::A), None);
    }
}
