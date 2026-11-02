// 学生アカウントのローカルパート: 英字1文字 + 数字7桁 (例: a0000000)
// 実際の採番規則と異なる場合はこのパターンを調整する
const STUDENT_ID_PATTERN = /^[a-z]\d{7}$/;

/**
 * メールアドレスのローカルパートから学籍番号を抽出する。
 * 教職員アカウントなど形式に合致しない場合は null を返す
 */
export function extractStudentId(email: string): string | null {
    const at = email.lastIndexOf("@");
    if (at <= 0) {
        return null;
    }
    const localPart = email.slice(0, at).toLowerCase();
    return STUDENT_ID_PATTERN.test(localPart) ? localPart : null;
}
