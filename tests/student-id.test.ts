import { describe, expect, it } from "vitest";
import { extractStudentId } from "../src/services/student-id.js";

describe("extractStudentId", () => {
    it("学生形式のローカルパートを学籍番号として返す", () => {
        expect(extractStudentId("a0000000@g.chuo-u.ac.jp")).toBe("a0000000");
        expect(extractStudentId("z1234567@g.chuo-u.ac.jp")).toBe("z1234567");
    });

    it("大文字は小文字に正規化する", () => {
        expect(extractStudentId("A1234567@g.chuo-u.ac.jp")).toBe("a1234567");
    });

    it("形式に合致しないアドレスは null", () => {
        expect(extractStudentId("taro.chuo@g.chuo-u.ac.jp")).toBeNull();
        expect(extractStudentId("a123456@g.chuo-u.ac.jp")).toBeNull();
        expect(extractStudentId("a12345678@g.chuo-u.ac.jp")).toBeNull();
        expect(extractStudentId("12345678@g.chuo-u.ac.jp")).toBeNull();
        expect(extractStudentId("a1234567+x@g.chuo-u.ac.jp")).toBeNull();
    });

    it("メールアドレスでない文字列は null", () => {
        expect(extractStudentId("")).toBeNull();
        expect(extractStudentId("a1234567")).toBeNull();
        expect(extractStudentId("@g.chuo-u.ac.jp")).toBeNull();
    });
});
