from flask import Blueprint, render_template, request
import requests

weather = Blueprint('weather', __name__)

@weather.route("/weather", methods=["GET", "POST"])
def weather_page():
    city = "Delhi"
    weather_data = []
    dates = []
    avg_temps = []
    max_temps = []
    min_temps = []
    humidities = []


    if request.method == "POST":
        user_city = request.form.get("city", "").strip()
        if user_city:
            city = user_city

    # Step 1: Convert city → coordinates (Open-Meteo Geocoding API)
    geo_url = f"https://geocoding-api.open-meteo.com/v1/search?name={city}&count=1&language=en&format=json"
    geo_response = requests.get(geo_url).json()

    if "results" not in geo_response or len(geo_response["results"]) == 0:
        # Invalid city → send empty list
        return render_template(
            "weather.html",
            weather_data=[],
            city=city,
            dates=[],
            avg_temps=[],
            max_temps=[],
            min_temps=[],
            humidities=[]
        )

    lat = geo_response["results"][0]["latitude"]
    lon = geo_response["results"][0]["longitude"]

    # Step 2: Fetch 16-day forecast
    forecast_url = (
        f"https://api.open-meteo.com/v1/forecast?"
        f"latitude={lat}&longitude={lon}"
        f"&daily=temperature_2m_max,temperature_2m_min,temperature_2m_mean,relative_humidity_2m_mean,weathercode"
        f"&timezone=auto"
        f"&forecast_days=16"
    )

    forecast_response = requests.get(forecast_url)
    res = forecast_response.json()

    # If API fails or doesn't return daily data, avoid crashing
    if forecast_response.status_code != 200 or "daily" not in res:
        return render_template(
            "weather.html",
            weather_data=[],
            city=city,
            dates=[],
            avg_temps=[],
            max_temps=[],
            min_temps=[],
            humidities=[],
            error=res.get("reason") or res.get("error") or "Weather data not available right now."
        )

    daily = res["daily"]

    dates = daily.get("time", [])
    avg_temps = daily.get("temperature_2m_mean", [])
    max_temps = daily.get("temperature_2m_max", [])
    min_temps = daily.get("temperature_2m_min", [])
    humidities = daily.get("relative_humidity_2m_mean", [])
    weather_codes = daily.get("weathercode", [])


    # Weather code → icon + description mapping
    weather_map = {
        0: ("☀️", "Clear sky"),
        1: ("🌤️", "Mainly clear"),
        2: ("⛅", "Partly cloudy"),
        3: ("☁️", "Overcast"),
        45: ("🌫️", "Foggy"),
        48: ("🌫️", "Depositing rime fog"),
        51: ("🌦️", "Light drizzle"),
        53: ("🌦️", "Moderate drizzle"),
        55: ("🌧️", "Dense drizzle"),
        61: ("🌦️", "Slight rain"),
        63: ("🌧️", "Moderate rain"),
        65: ("🌧️", "Heavy rain"),
        71: ("🌨️", "Light snow"),
        73: ("🌨️", "Moderate snow"),
        75: ("❄️", "Heavy snow"),
        80: ("🌦️", "Rain showers"),
        81: ("🌧️", "Rain showers"),
        82: ("🌧️⛈️", "Violent rain showers"),
        95: ("⛈️", "Thunderstorm"),
    }

    # Build unified weather_data list for your cards
    weather_data = []
    for i in range(len(dates)):
        code = weather_codes[i]
        icon, desc = weather_map.get(code, ("🌥️", "Unknown"))
        weather_data.append({
            "date": dates[i],
            "avg": avg_temps[i],
            "max": max_temps[i],
            "min": min_temps[i],
            "humidity": humidities[i],
            "icon": icon,
            "text": desc
        })

    return render_template(
        "weather.html",
        weather_data=weather_data,
        city=city,
        dates=dates,
        avg_temps=avg_temps,
        max_temps=max_temps,
        min_temps=min_temps,
        humidities=humidities,
    )
