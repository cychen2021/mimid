package utils;

public enum TaintType {
    DEFAULT,
    STRLEN,
    TOKEN,
    STRCONST,
    CONVERTEDNUMBER // a taint for strings that are converted to an integer, float and the like
}
