use super::super::generate;
use super::specification;
use std::io::Cursor;

#[test]
fn typedef_void() {
    let s = specification(
        r#"
typedef void;           /* syntactically defined, semantically meaningless  */
"#,
    );

    println!("spec {:?}", s);
    assert!(s.is_err())
}

#[test]
fn kwishnames() {
    let kws = vec![
        "bool",
        "case",
        "const",
        "default",
        "double",
        "enum",
        "float",
        "hyper",
        "int",
        "opaque",
        "quadruple",
        "string",
        "struct",
        "switch",
        "typedef",
        "union",
        "unsigned",
        "void",
    ];
    let specs = vec![
        "const {}x = 1;",
        "struct {}x { int i; };",
        "struct foo { int {}x; };",
        "typedef int {}x;",
        "union {}x switch (int x) { case 1: void; };",
        "union x switch (int {}x) { case 1: void; };",
        "union x switch (int y) { case 1: int {}x; };",
    ];

    for sp in &specs {
        for kw in &kws {
            let spec = sp.replace("{}", kw);
            let s = specification(&spec);
            println!("spec {} => {:?}", spec, s);
            assert!(s.is_ok())
        }
    }
}

#[test]
fn kwnames() {
    let kws = vec![
        "bool",
        "case",
        "const",
        "default",
        "double",
        "enum",
        "float",
        "hyper",
        "int",
        "opaque",
        "quadruple",
        "string",
        "struct",
        "switch",
        "typedef",
        "union",
        "unsigned",
        "void",
    ];
    let specs = vec![
        "const {} = 1;",
        "struct {} { int i; };",
        "struct foo { int {}; };",
        "typedef int {};",
        "union {} switch (int x) { case 1: void; };",
        "union x switch (int {}) { case 1: void; };",
        "union x switch (int y) { case 1: int {}; };",
    ];

    for sp in &specs {
        for kw in &kws {
            let spec = sp.replace("{}", kw);
            let s = specification(&spec);
            println!("spec {} => {:?}", spec, s);
            assert!(s.is_err())
        }
    }
}

#[test]
fn inline_struct() {
    let spec = r#"
        struct thing {
                struct { int a; int b; } thing;
        };
"#;
    let s = specification(spec);

    println!("spec {:?}", s);
    assert!(s.is_ok());

    let g = generate("", Cursor::new(spec.as_bytes()), Vec::new());
    assert!(g.is_err());
}

#[test]
fn inline_union() {
    let spec = r#"
        struct thing {
                union switch(int x) { case 0: int a; case 1: int b; } thing;
        };
"#;
    let s = specification(spec);

    println!("spec {:?}", s);
    assert!(s.is_ok());

    let g = generate("", Cursor::new(spec.as_bytes()), Vec::new());
    assert!(g.is_err());
}

#[test]
fn case_type() {
    let specs = vec![
        "enum Foo { A, B, C }; union Bar switch (Foo x) { case A: void; case B: void; case C: void; };",
        "union Bar switch (int x) { case 1: void; case 2: void; case 3: void; };",
    ];

    for sp in specs {
        let s = specification(sp);
        println!("spec sp \"{}\" => {:?}", sp, s);
        assert!(s.is_ok());

        let g = generate("", Cursor::new(sp.as_bytes()), Vec::new());
        assert!(g.is_ok());
    }
}

#[test]
fn case_type_mismatch() {
    let specs = vec![
        "enum Foo { A, B, C}; union Bar switch (Foo x) { case 1: void; case 2: void; case 3: void; };",
        "enum Foo { A, B, C}; union Bar switch (int x) { case A: void; case B: void; case C: void; };",
    ];

    for sp in specs {
        let s = specification(sp);
        println!("spec sp \"{}\" => {:?}", sp, s);
        assert!(s.is_ok());

        let g = generate("", Cursor::new(sp.as_bytes()), Vec::new());
        assert!(g.is_err());
    }
}

#[test]
fn constants() {
    let specs = vec![
        "const A = 0;",
        "const A = 0x0;",
        "const A = 00;",
        "const A = -0;",
        "const A = 0x123;",
        "const A = 0123;",
        "const A = -0123;",
        "const A = 123;",
        "const A = -123;",
    ];

    for sp in specs {
        let s = specification(sp);
        println!("spec sp \"{}\" => {:?}", sp, s);
        assert!(s.is_ok());

        let g = generate("", Cursor::new(sp.as_bytes()), Vec::new());
        assert!(g.is_ok());
    }
}

#[test]
fn union_simple() {
    let s = specification(
        r#"
union foo switch (int x) {
case 0:
    int val;
};
"#,
    );
    println!("spec {:?}", s);
    assert!(s.is_ok())
}

#[test]
fn union_default() {
    let s = specification(
        r#"
union foo switch (int x) {
case 0:
    int val;
default:
    void;
};
"#,
    );
    println!("spec {:?}", s);
    assert!(s.is_ok())
}

#[test]
fn union_default_nonempty() {
    let s = specification(
        r#"
union foo switch (int x) {
case 0:
    int val;
default:
    bool bye;
};
"#,
    );
    println!("spec {:?}", s);
    assert!(s.is_ok())
}

#[test]
fn fallthrough_case() {
    let s = specification(
        r#"
union foo switch (int x) {
  case 0:
  case 1:
       int val;
  case 2:
       void;
};
"#,
    );
    println!("spec {:?}", s);
    assert!(s.is_ok())
}
