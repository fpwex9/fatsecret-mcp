# FatSecret MCP Server (Extended)

An extended [Model Context Protocol](https://modelcontextprotocol.io/) server for the [FatSecret Platform API](https://platform.fatsecret.com/). Provides **25 tools** for comprehensive food diary management via Claude Desktop, Claude Code, or any MCP-compatible client.

> Fork of [fcoury/fatsecret-mcp](https://github.com/fcoury/fatsecret-mcp) with 17 additional API methods, bug fixes, and meal type mapping.

## What's New (vs Original)

- **17 new tools**: diary editing/deletion, monthly nutrition summary, favorites, saved meals CRUD, weight logging, barcode search, autocomplete
- **Bug fixes**: correct `food_entry_name` / `saved_meal_item_name` params, `number_of_units` instead of `quantity`, `snack` mapped to `other` for API compatibility
- Full OAuth 1.0a support (unchanged from original)

## All 25 Tools

### Authentication (3)

| Tool | Description |
|------|-------------|
| `set_credentials` | Set FatSecret API credentials (Client ID and Client Secret) |
| `start_oauth_flow` | Start the 3-legged OAuth flow to get user authorization |
| `complete_oauth_flow` | Complete the OAuth flow with the authorization code/verifier |

### Food Database (4)

| Tool | Description |
|------|-------------|
| `search_foods` | Search for foods in the FatSecret database |
| `get_food` | Get detailed nutrition info for a specific food |
| `autocomplete_foods` | Get food name suggestions as you type (max 10 results) |
| `barcode_search` | Search for a food by barcode (EAN/UPC 13-digit GTIN) |

### Recipes (2)

| Tool | Description |
|------|-------------|
| `search_recipes` | Search for recipes |
| `get_recipe` | Get detailed recipe info including ingredients and directions |

### Food Diary (5)

| Tool | Description |
|------|-------------|
| `get_user_food_entries` | Get diary entries for a specific date |
| `add_food_entry` | Add a food entry to the diary |
| `edit_food_entry` | Edit an existing entry (change quantity, serving, or meal) |
| `delete_food_entry` | Delete a food entry from the diary |
| `get_food_entries_month` | Get summarized daily nutrition (cal, protein, fat, carbs) for a month |

### Quick Search (3)

| Tool | Description |
|------|-------------|
| `get_most_eaten` | Get the user's most frequently eaten foods |
| `get_recently_eaten` | Get the user's recently eaten foods |
| `check_auth_status` | Check if the user is authenticated |

### Favorites (3)

| Tool | Description |
|------|-------------|
| `get_favorites` | Get the user's favorite foods list |
| `add_favorite` | Add a food to favorites |
| `delete_favorite` | Remove a food from favorites |

### Saved Meals (6)

| Tool | Description |
|------|-------------|
| `get_saved_meals` | Get all saved meals |
| `create_saved_meal` | Create a new saved meal |
| `delete_saved_meal` | Delete a saved meal |
| `get_saved_meal_items` | Get all food items in a saved meal |
| `add_saved_meal_item` | Add a food item to a saved meal |
| `delete_saved_meal_item` | Remove a food item from a saved meal |

### Weight & Profile (3)

| Tool | Description |
|------|-------------|
| `get_user_profile` | Get the authenticated user's profile |
| `get_weight_month` | Get weight entries for a specific month |
| `update_weight` | Record weight for a specific date (within 2 days of today) |

## Installation

```bash
git clone https://github.com/fpwex9/fatsecret-mcp.git
cd fatsecret-mcp
npm install
npm run build
```

## Setup

### 1. Get API Credentials

1. Go to [FatSecret Platform](https://platform.fatsecret.com/)
2. Create a developer account and register an application
3. Note your **Consumer Key** (Client ID) and **Consumer Secret** (Client Secret)
4. These are OAuth 1.0a credentials (not OAuth 2.0)

### 2. Connect to Claude Desktop

Add to your Claude Desktop config (`~/Library/Application Support/Claude/claude_desktop_config.json` on macOS):

```json
{
  "mcpServers": {
    "fatsecret": {
      "command": "node",
      "args": ["/absolute/path/to/fatsecret-mcp/dist/index.js"]
    }
  }
}
```

### 3. Connect to Claude Code CLI

```bash
claude mcp add --scope user fatsecret node /absolute/path/to/fatsecret-mcp/dist/index.js
```

### 4. Authenticate

In Claude, use the MCP tools:

1. `set_credentials` with your Client ID and Client Secret
2. `start_oauth_flow` (callbackUrl: "oob")
3. Visit the authorization URL, log in, click Allow, copy the verifier code
4. `complete_oauth_flow` with requestToken, requestTokenSecret, and verifier

Credentials and tokens are saved in `~/.fatsecret-mcp-config.json`.

## Usage Examples

### Log a meal

```
"I had 200g of chicken breast and 150g of rice for lunch"

Claude will:
1. search_foods("chicken breast") → get serving_id for 100g
2. search_foods("white rice cooked") → get serving_id for 100g
3. add_food_entry for each (quantity=2 and 1.5 respectively, mealType="lunch")
```

### Edit a diary entry

```
"Change my chicken to 150g"

Claude will:
1. get_user_food_entries for today
2. find the chicken entry → food_entry_id
3. edit_food_entry(foodEntryId, quantity=1.5)
```

### Monthly nutrition summary

```
"How did my protein look this month?"

Claude will:
1. get_food_entries_month(date="2026-02-01")
2. Show daily protein totals in a table
```

### Repeat yesterday's breakfast

```
"Log the same breakfast as yesterday"

Claude will:
1. get_user_food_entries(date=yesterday) → filter breakfast entries
2. add_food_entry for each item on today's date
```

### Search by barcode

```
"Look up barcode 0049000006346"

Claude will:
1. barcode_search(barcode="0049000006346") → food_id
2. get_food(food_id) → Coca-Cola Classic, 140 kcal
```

## API Tier Notes

- **Basic** (free): 5,000 calls/day, US market only
- **Premier Free**: Unlimited calls, US market + extra markets at 50% discount. Includes barcode search and autocomplete.
- **Premier** (paid): 56+ countries, custom food creation (`food.create.v2`)

The `food.create.v2` method (create custom foods) is **not available** on Premier Free. Barcode search works best with US UPC codes; European EAN codes may not return results on non-Premier plans.

## Configuration

Credentials are stored in `~/.fatsecret-mcp-config.json`:

```json
{
  "clientId": "your_consumer_key",
  "clientSecret": "your_consumer_secret",
  "accessToken": "saved_after_oauth",
  "accessTokenSecret": "saved_after_oauth"
}
```

## Troubleshooting

| Problem | Solution |
|---------|----------|
| "Invalid signature" on OAuth | Make sure you're using OAuth 1.0a Consumer Secret, not OAuth 2.0 Client Secret |
| "Invalid Type: meal is invalid" | Use "breakfast", "lunch", "dinner", or "snack" (mapped to "other" internally) |
| "Missing required parameter: food_entry_name" | Update to latest version (fixed in this fork) |
| Barcode returns food_id=0 | Product not in database for your API tier/region |
| Server not found in Claude | Use absolute path in config, verify `npm run build` succeeded |
| "User authentication required" | Complete the OAuth flow first, check with `check_auth_status` |

## Development

```bash
npm install
npm run build    # compile TypeScript
npm start        # run the server
```

All tools are in `src/index.ts` in the `FatSecretMCPServer` class. Pattern for adding new tools:

1. Add tool definition in `ListToolsRequestSchema` handler
2. Add case in `CallToolRequestSchema` switch
3. Implement handler method using `makeApiRequest()`

## Credits

- Original: [fcoury/fatsecret-mcp](https://github.com/fcoury/fatsecret-mcp)
- API: [FatSecret Platform API](https://platform.fatsecret.com/)

## License

MIT License - see LICENSE file for details.
