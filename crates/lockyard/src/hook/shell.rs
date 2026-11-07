// Copyright 2026 The Lockyard Authors. Licensed under the Apache License, Version 2.0.

pub(super) fn command_is_heavy(line: &str, patterns: &[String]) -> bool {
    split_simple_commands(line)
        .into_iter()
        .filter_map(|part| shell_words(part).filter(|words| !words.is_empty()))
        .any(|mut words| {
            if let Some(first) = words.first_mut() {
                *first = first.trim_start_matches('(').to_string();
            }
            if let Some(last) = words.last_mut() {
                *last = last.trim_end_matches(')').to_string();
            }
            if words.first().is_some_and(|word| word == "sudo") {
                words.remove(0);
                while words.first().is_some_and(|word| word.starts_with('-')) {
                    let option = words.remove(0);
                    if matches!(option.as_str(), "-u" | "-g" | "-h" | "-p" | "-C" | "-T")
                        && !words.is_empty()
                    {
                        words.remove(0);
                    }
                }
            }
            if words.first().is_some_and(|word| word == "env") {
                words.remove(0);
                while words.first().is_some_and(|word| is_env_assignment(word)) {
                    words.remove(0);
                }
            }
            while words.first().is_some_and(|word| is_env_assignment(word)) {
                words.remove(0);
            }
            while let Some(wrapper) = words.first().map(String::as_str) {
                match wrapper {
                    "time" if words.get(1).is_some_and(|word| word.starts_with('-')) => {
                        words.remove(0);
                        while words.first().is_some_and(|word| word.starts_with('-')) {
                            words.remove(0);
                        }
                    }
                    "time" | "nohup" => {
                        words.remove(0);
                    }
                    "nice" => {
                        words.remove(0);
                        if words.first().is_some_and(|word| word == "-n") {
                            words.remove(0);
                            if !words.is_empty() {
                                words.remove(0);
                            }
                        } else if words.first().is_some_and(|word| {
                            word.starts_with('-') && word[1..].chars().all(|c| c.is_ascii_digit())
                        }) {
                            words.remove(0);
                        }
                    }
                    "timeout" => {
                        words.remove(0);
                        while words.first().is_some_and(|word| word.starts_with('-')) {
                            words.remove(0);
                        }
                        if !words.is_empty() {
                            words.remove(0);
                        }
                    }
                    _ => break,
                }
            }
            let program = words
                .first()
                .map(|word| word.rsplit('/').next().unwrap_or(word));
            if program.is_some_and(|word| word == "lockyard")
                && words.get(1).is_some_and(|word| word == "run")
            {
                return false;
            }
            patterns.iter().any(|pattern| {
                let wanted = match shell_words(pattern) {
                    Some(words) if !words.is_empty() => words,
                    _ => return false,
                };
                !wanted.is_empty()
                    && program == wanted.first().map(String::as_str)
                    && words
                        .get(1..wanted.len())
                        .is_some_and(|tail| tail == &wanted[1..])
            })
        })
}

pub(super) fn split_simple_commands(line: &str) -> Vec<&str> {
    let (mut result, mut start, mut quote, mut escaped) = (Vec::new(), 0, None, false);
    for (index, ch) in line.char_indices() {
        if escaped {
            escaped = false;
            continue;
        }
        if ch == '\\' && quote != Some('\'') {
            escaped = true;
            continue;
        }
        if let Some(q) = quote {
            if ch == q {
                quote = None;
            }
            continue;
        }
        if ch == '\'' || ch == '"' {
            quote = Some(ch);
        } else if matches!(ch, '\n' | ';' | '|' | '&') {
            result.push(&line[start..index]);
            start = index + ch.len_utf8();
        }
    }
    result.push(&line[start..]);
    result
}

pub(super) fn is_env_assignment(word: &str) -> bool {
    word.split_once('=').is_some_and(|(name, _)| {
        !name.is_empty()
            && name
                .chars()
                .enumerate()
                .all(|(i, c)| c == '_' || c.is_ascii_alphabetic() || (i > 0 && c.is_ascii_digit()))
    })
}

pub(super) fn shell_words(input: &str) -> Option<Vec<String>> {
    let (mut words, mut word, mut quote, mut escaped, mut active) =
        (Vec::new(), String::new(), None, false, false);
    for ch in input.chars() {
        if escaped {
            word.push(ch);
            escaped = false;
            active = true;
            continue;
        }
        if ch == '\\' && quote != Some('\'') {
            escaped = true;
            active = true;
            continue;
        }
        if let Some(q) = quote {
            if ch == q {
                quote = None;
            } else {
                word.push(ch);
            }
        } else if ch == '\'' || ch == '"' {
            quote = Some(ch);
            active = true;
        } else if ch.is_whitespace() {
            if active {
                words.push(std::mem::take(&mut word));
                active = false;
            }
        } else {
            word.push(ch);
            active = true;
        }
    }
    if quote.is_some() || escaped {
        return None;
    }
    if active {
        words.push(word);
    }
    Some(words)
}
