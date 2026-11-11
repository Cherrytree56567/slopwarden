package com.ct5.clientwarden.wear

import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.BasicText
import androidx.compose.foundation.text.BasicTextField
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.SolidColor
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.input.VisualTransformation
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.TextUnit
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp

/*
 * The watch's colours. Deliberately all-dark and mostly monochrome: an always-on style OLED
 * screen saves the most power on black, and one accent colour is enough at this size.
 */
object Palette {
    val Bg = Color(0xFF000000)
    val Panel = Color(0xFF16161A)
    val PanelHigh = Color(0xFF24242A)
    val Ink = Color(0xFFF2F2F5)
    val Muted = Color(0xFF8B8B95)
    val Accent = Color(0xFF7CD4FD)
    val Danger = Color(0xFFFF7A7A)
}

@Composable
fun Label(
    text: String,
    size: TextUnit = 14.sp,
    color: Color = Palette.Ink,
    weight: FontWeight = FontWeight.Normal,
    maxLines: Int = Int.MAX_VALUE,
    modifier: Modifier = Modifier,
) {
    BasicText(
        text = text,
        modifier = modifier,
        style = TextStyle(color = color, fontSize = size, fontWeight = weight),
        maxLines = maxLines,
        overflow = TextOverflow.Ellipsis,
    )
}

/*
 * A tappable panel. Everything on the watch is a big touch target; 48dp is the smallest a
 * gloved finger can reliably hit.
 */
@Composable
fun Panel(
    onClick: (() -> Unit)? = null,
    enabled: Boolean = true,
    background: Color = Palette.Panel,
    modifier: Modifier = Modifier,
    content: @Composable () -> Unit,
) {
    Box(
        modifier = modifier
            .fillMaxWidth()
            .clip(RoundedCornerShape(20.dp))
            .background(background)
            .then(if (onClick != null && enabled) Modifier.clickable { onClick() } else Modifier)
            .padding(horizontal = 14.dp, vertical = 12.dp),
        contentAlignment = Alignment.CenterStart,
    ) {
        content()
    }
}

@Composable
fun WatchButton(
    label: String,
    enabled: Boolean = true,
    danger: Boolean = false,
    onClick: () -> Unit,
) {
    val fill = when {
        !enabled -> Palette.Panel
        danger -> Palette.PanelHigh
        else -> Palette.Accent
    }
    val ink = when {
        !enabled -> Palette.Muted
        danger -> Palette.Danger
        else -> Color.Black
    }
    Panel(onClick = onClick, enabled = enabled, background = fill) {
        Box(Modifier.fillMaxWidth(), contentAlignment = Alignment.Center) {
            Label(label, size = 15.sp, color = ink, weight = FontWeight.Medium)
        }
    }
}

@Composable
fun WatchField(
    value: String,
    onValueChange: (String) -> Unit,
    placeholder: String,
    enabled: Boolean = true,
    password: Boolean = false,
    keyboardType: KeyboardType = KeyboardType.Text,
    imeAction: ImeAction = ImeAction.Done,
) {
    Panel(background = Palette.Panel) {
        Box(Modifier.fillMaxWidth().padding(vertical = 2.dp)) {
            if (value.isEmpty()) {
                Label(placeholder, color = Palette.Muted, maxLines = 1)
            }
            BasicTextField(
                value = value,
                onValueChange = { if (enabled) onValueChange(it) },
                enabled = enabled,
                singleLine = true,
                textStyle = TextStyle(
                    color = if (enabled) Palette.Ink else Palette.Muted,
                    fontSize = 15.sp,
                ),
                cursorBrush = SolidColor(Palette.Accent),
                visualTransformation = if (password) PasswordVisualTransformation() else VisualTransformation.None,
                keyboardOptions = KeyboardOptions(keyboardType = keyboardType, imeAction = imeAction),
                modifier = Modifier.fillMaxWidth(),
            )
        }
    }
}

/*
 * A labelled row: what it is on the left, the value underneath, tapping copies.
 */
@Composable
fun CopyRow(label: String, value: String, onCopy: () -> Unit) {
    Panel(onClick = onCopy) {
        Column(verticalArrangement = Arrangement.spacedBy(2.dp)) {
            Label(label, size = 11.sp, color = Palette.Muted)
            Label(value, size = 15.sp, maxLines = 1)
        }
    }
}

@Composable
fun Row2(left: @Composable () -> Unit, right: @Composable () -> Unit) {
    Row(
        Modifier.fillMaxWidth(),
        horizontalArrangement = Arrangement.spacedBy(8.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Box(Modifier.weight(1f)) { left() }
        Box(Modifier.weight(1f)) { right() }
    }
}

@Composable
fun Screen(content: @Composable () -> Unit) {
    Box(Modifier.fillMaxSize().background(Palette.Bg)) {
        content()
    }
}
