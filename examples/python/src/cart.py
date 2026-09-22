"""A shopping cart that stores integer cents and discounts in basis points."""

from money import add_all, percent_of, units_to_text

BPS = 10000
FREE_SHIPPING_CENTS = 5000
SHIPPING_CENTS = 495
MAX_LINES = 50


class Cart:
    def __init__(self, owner: str) -> None:
        self.owner = owner
        self.lines = []
        self.coupon_bps = 0

    def add(self, sku: str, unit_price: int, quantity: int) -> None:
        if quantity < 1 or quantity > MAX_LINES:
            raise ValueError("quantity must be between 1 and 50")
        self.lines.append((sku, unit_price * quantity))

    def subtotal(self) -> int:
        return add_all([total for _, total in self.lines])

    def discount(self) -> int:
        return percent_of(self.subtotal(), self.coupon_bps * 100 / BPS)

    def payable(self) -> int:
        net = self.subtotal() - self.discount()
        if net >= FREE_SHIPPING_CENTS:
            return net
        return net + SHIPPING_CENTS

    def receipt(self) -> str:
        rows = [f"{self.owner}"]
        for sku, total in self.lines:
            rows.append(f"{sku} {units_to_text(total)}")
        rows.append(f"payable {units_to_text(self.payable())}")
        return "\n".join(rows)
